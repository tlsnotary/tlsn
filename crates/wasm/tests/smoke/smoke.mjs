// Runtime smoke test for the built `pkg/` artifact.
//
// Serves pkg/ with the cross-origin isolation headers the shared-memory module
// needs, loads it in a real (headless) Chrome, and asserts the public API works:
// construct Prover/Verifier, and run compute_reveal. Run `./build.sh` first
// (or use `./test-package.sh`).

import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import puppeteer from "puppeteer-core";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgDir = path.resolve(here, "../../pkg");
const pagePath = path.join(here, "page.mjs");

if (!existsSync(path.join(pkgDir, "tlsn_wasm.js"))) {
    console.error(`error: ${pkgDir}/tlsn_wasm.js not found; run ./build.sh first`);
    process.exit(1);
}

const MIME = {
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".wasm": "application/wasm",
    ".json": "application/json",
    ".html": "text/html",
};

const indexHtml =
    '<!doctype html><meta charset="utf-8"><title>tlsn smoke</title>' +
    '<script type="module" src="/__smoke__.mjs"></script>';

const server = http.createServer(async (req, res) => {
    try {
        res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
        res.setHeader("Cache-Control", "no-store");

        const { pathname } = new URL(req.url, "http://localhost");
        if (pathname === "/") {
            res.setHeader("Content-Type", "text/html");
            res.end(indexHtml);
            return;
        }
        if (pathname === "/__smoke__.mjs") {
            res.setHeader("Content-Type", "text/javascript");
            res.end(await readFile(pagePath));
            return;
        }

        const filePath = path.join(pkgDir, decodeURIComponent(pathname));
        if (!filePath.startsWith(pkgDir) || !existsSync(filePath)) {
            res.statusCode = 404;
            res.end("not found");
            return;
        }
        res.setHeader(
            "Content-Type",
            MIME[path.extname(filePath)] ?? "application/octet-stream",
        );
        res.end(await readFile(filePath));
    } catch (err) {
        res.statusCode = 500;
        res.end(String(err));
    }
});

function findChrome() {
    const candidates = [
        process.env.CHROME_PATH,
        "/usr/local/bin/google-chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ];
    for (const candidate of candidates) {
        if (candidate && existsSync(candidate)) return candidate;
    }
    for (const bin of ["google-chrome", "google-chrome-stable", "chromium", "chrome"]) {
        try {
            const resolved = execSync(`command -v ${bin}`).toString().trim();
            if (resolved) return resolved;
        } catch {
            // not found, try the next one
        }
    }
    throw new Error("Chrome not found; set CHROME_PATH");
}

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address();

const browser = await puppeteer.launch({
    executablePath: findChrome(),
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

let exitCode = 0;
try {
    const page = await browser.newPage();
    page.on("console", (msg) => console.error("[browser]", msg.text()));
    page.on("pageerror", (err) => console.error("[pageerror]", err.message));

    await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "load" });
    await page.waitForFunction("window.__smoke !== undefined", { timeout: 30_000 });
    const result = await page.evaluate(() => window.__smoke);

    console.log(JSON.stringify(result, null, 2));

    const failedChecks = Object.entries(result.checks ?? {})
        .filter(([, value]) => value === false)
        .map(([name]) => name);

    if (!result.ok || failedChecks.length > 0) {
        console.error(
            `smoke failed${failedChecks.length ? `: ${failedChecks.join(", ")}` : ""}`,
        );
        exitCode = 1;
    } else {
        console.log("smoke OK");
    }
} finally {
    await browser.close();
    server.close();
}

process.exit(exitCode);
