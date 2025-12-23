use std::f32;

use charming::{
    Chart, HtmlRenderer, ImageRenderer,
    component::{Axis, Legend, Title},
    element::{AreaStyle, LineStyle, NameLocation, Orient, TextStyle, Tooltip, Trigger},
    series::Line,
    theme::Theme,
};
use clap::Parser;
use harness_core::bench::BenchItems;
use polars::prelude::*;

const THEME: Theme = Theme::Default;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Path to the Bench.toml file with benchmark spec
    toml: String,

    /// Path to the CSV file with benchmark results
    csv: String,

    /// Prover kind: native or browser
    #[arg(short, long, value_enum, default_value = "native")]
    prover_kind: ProverKind,

    /// Add min/max bands to plots
    #[arg(long, default_value_t = false)]
    min_max_band: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ProverKind {
    Native,
    Browser,
}

impl std::fmt::Display for ProverKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProverKind::Native => write!(f, "Native"),
            ProverKind::Browser => write!(f, "Browser"),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let df = CsvReadOptions::default()
        .try_into_reader_with_file_path(Some(cli.csv.clone().into()))?
        .finish()?;

    let items: BenchItems = toml::from_str(&std::fs::read_to_string(&cli.toml)?)?;
    let groups = items.group;

    for group in groups {
        if group.protocol_latency.is_some() {
            let latency = group.protocol_latency.unwrap();
            plot_runtime_vs(
                &df,
                cli.min_max_band,
                &group.name,
                "bandwidth",
                1.0 / 1000.0, // Kbps to Mbps
                "Runtime vs Bandwidth",
                format!("{} ms Latency, {} mode", latency, cli.prover_kind),
                "runtime_vs_bandwidth",
                "Bandwidth (Mbps)",
            )?;
        }

        if group.bandwidth.is_some() {
            let bandwidth = group.bandwidth.unwrap();
            plot_runtime_vs(
                &df,
                cli.min_max_band,
                &group.name,
                "latency",
                1.0,
                "Runtime vs Latency",
                format!("{} bps bandwidth, {} mode", bandwidth, cli.prover_kind),
                "runtime_vs_latency",
                "Latency (ms)",
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn plot_runtime_vs(
    df: &DataFrame,
    show_min_max: bool,
    group: &str,
    x_col: &str,
    x_scale: f32,
    title: &str,
    subtitle: String,
    output_file: &str,
    x_axis_label: &str,
) -> Result<Chart, Box<dyn std::error::Error>> {
    let stats_df = df
        .clone()
        .lazy()
        .filter(col("group").eq(lit(group)))
        .with_column((col(x_col).cast(DataType::Float32) * lit(x_scale)).alias("x"))
        .with_columns([
            (col("time_preprocess").cast(DataType::Float32) / lit(1000.0)).alias("preprocess"),
            (col("time_online").cast(DataType::Float32) / lit(1000.0)).alias("online"),
            (col("time_total").cast(DataType::Float32) / lit(1000.0)).alias("total"),
        ])
        .group_by([col("x")])
        .agg([
            col("preprocess").min().alias("preprocess_min"),
            col("preprocess").mean().alias("preprocess_mean"),
            col("preprocess").max().alias("preprocess_max"),
            col("online").min().alias("online_min"),
            col("online").mean().alias("online_mean"),
            col("online").max().alias("online_max"),
            col("total").min().alias("total_min"),
            col("total").mean().alias("total_mean"),
            col("total").max().alias("total_max"),
        ])
        .sort(["x"], Default::default())
        .collect()?;

    let mut chart = Chart::new()
        .title(
            Title::new()
                .text(title)
                .left("center")
                .subtext(subtitle)
                .subtext_style(TextStyle::new().font_size(16)),
        )
        .tooltip(Tooltip::new().trigger(Trigger::Axis))
        .legend(
            Legend::new()
                .data(vec!["Preprocess Mean", "Online Mean", "Total Mean"])
                .top("80")
                .right("110")
                .orient(Orient::Vertical)
                .item_gap(10),
        )
        .x_axis(
            Axis::new()
                .name(x_axis_label)
                .scale(true)
                .name_location(NameLocation::Middle)
                .name_gap(30)
                .name_text_style(TextStyle::new().font_size(21)),
        )
        .y_axis(
            Axis::new()
                .name("Time (seconds)")
                .scale(true)
                .name_location(NameLocation::Middle)
                .name_rotation(90)
                .name_gap(30)
                .name_text_style(TextStyle::new().font_size(21)),
        );

    chart = add_mean_series(&chart, &stats_df, "Preprocess Mean", "preprocess_mean")?;
    chart = add_mean_series(&chart, &stats_df, "Online Mean", "online_mean")?;
    chart = add_mean_series(&chart, &stats_df, "Total Mean", "total_mean")?;

    if show_min_max {
        chart = add_min_max_band(
            &chart,
            &stats_df,
            "Preprocess Min/Max",
            "preprocess",
            "#ccc",
        )?;
        chart = add_min_max_band(&chart, &stats_df, "Online Min/Max", "online", "#ccc")?;
        chart = add_min_max_band(&chart, &stats_df, "Total Min/Max", "total", "#ccc")?;
    }
    // Save the chart as HTML file.
    HtmlRenderer::new(title, 1000, 800)
        .theme(THEME)
        .save(&chart, &format!("{}.html", output_file))
        .unwrap();

    ImageRenderer::new(1000, 800)
        .theme(THEME)
        .save(&chart, &format!("{}.svg", output_file))
        .unwrap();

    Ok(chart)
}

fn add_mean_series(
    chart: &Chart,
    df: &DataFrame,
    name: &str,
    col_name: &str,
) -> Result<Chart, Box<dyn std::error::Error>> {
    let x = df.column("x")?.f32()?;
    let y = df.column(col_name)?.f32()?;

    let data: Vec<Vec<f32>> = x
        .into_iter()
        .zip(y.into_iter())
        .filter_map(|(x, y)| Some(vec![x?, y?]))
        .collect();

    Ok(chart
        .clone()
        .series(Line::new().name(name).data(data).symbol_size(6)))
}

fn add_min_max_band(
    chart: &Chart,
    df: &DataFrame,
    name: &str,
    col_prefix: &str,
    color: &str,
) -> Result<Chart, Box<dyn std::error::Error>> {
    let x = df.column("x")?.f32()?;
    let min_col = df.column(&format!("{}_min", col_prefix))?.f32()?;
    let max_col = df.column(&format!("{}_max", col_prefix))?.f32()?;

    let max_data: Vec<Vec<f32>> = x
        .into_iter()
        .zip(max_col.into_iter())
        .filter_map(|(x, y)| Some(vec![x?, y?]))
        .collect();

    let min_data: Vec<Vec<f32>> = x
        .into_iter()
        .zip(min_col.into_iter())
        .filter_map(|(x, y)| Some(vec![x?, y?]))
        .rev()
        .collect();

    let data: Vec<Vec<f32>> = max_data.into_iter().chain(min_data).collect();

    Ok(chart.clone().series(
        Line::new()
            .name(name)
            .data(data)
            .show_symbol(false)
            .line_style(LineStyle::new().opacity(0.0))
            .area_style(AreaStyle::new().opacity(0.3).color(color)),
    ))
}
