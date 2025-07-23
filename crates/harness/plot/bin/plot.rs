use std::f32;

use charming::{
    Chart, HtmlRenderer,
    component::{Axis, Legend, Title},
    element::{AreaStyle, LineStyle, NameLocation, Orient, TextStyle, Tooltip, Trigger},
    series::Line,
    theme::Theme,
};
use clap::Parser;
use harness_core::bench::{BenchItems, Measurement};
use itertools::Itertools;

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

    let mut rdr = csv::Reader::from_path(&cli.csv)?;

    let items: BenchItems = toml::from_str(&std::fs::read_to_string(&cli.toml)?)?;
    let groups = items.group;

    // Prepare data for plotting.
    let all_data: Vec<Measurement> = rdr
        .deserialize::<Measurement>()
        .collect::<Result<Vec<_>, _>>()?;

    for group in groups {
        if group.protocol_latency.is_some() {
            let latency = group.protocol_latency.unwrap();
            plot_runtime_vs(
                &all_data,
                cli.min_max_band,
                &group.name,
                |r| r.bandwidth as f32 / 1000.0, // Kbps to Mbps
                "Runtime vs Bandwidth",
                format!("{} ms Latency, {} mode", latency, cli.prover_kind),
                "runtime_vs_bandwidth.html",
                "Bandwidth (Mbps)",
            )?;
        }

        if group.bandwidth.is_some() {
            let bandwidth = group.bandwidth.unwrap();
            plot_runtime_vs(
                &all_data,
                cli.min_max_band,
                &group.name,
                |r| r.latency as f32,
                "Runtime vs Latency",
                format!("{} bps bandwidth, {} mode", bandwidth, cli.prover_kind),
                "runtime_vs_latency.html",
                "Latency (ms)",
            )?;
        }
    }

    Ok(())
}

struct DataPoint {
    min: f32,
    mean: f32,
    max: f32,
}

struct Points {
    preprocess: DataPoint,
    online: DataPoint,
    total: DataPoint,
}

#[allow(clippy::too_many_arguments)]
fn plot_runtime_vs<Fx>(
    all_data: &[Measurement],
    show_min_max: bool,
    group: &str,
    x_value: Fx,
    title: &str,
    subtitle: String,
    output_file: &str,
    x_axis_label: &str,
) -> Result<Chart, Box<dyn std::error::Error>>
where
    Fx: Fn(&Measurement) -> f32,
{
    fn data_point(values: &[f32]) -> DataPoint {
        let mean = values.iter().copied().sum::<f32>() / values.len() as f32;
        let max = values.iter().copied().reduce(f32::max).unwrap_or_default();
        let min = values.iter().copied().reduce(f32::min).unwrap_or_default();
        DataPoint { min, mean, max }
    }

    let stats: Vec<(f32, Points)> = all_data
        .iter()
        .filter(|r| r.group.as_deref() == Some(group))
        .map(|r| {
            (
                x_value(r),
                r.time_preprocess as f32 / 1000.0, // ms to s
                r.time_online as f32 / 1000.0,
                r.time_total as f32 / 1000.0,
            )
        })
        .sorted_by(|a, b| a.0.partial_cmp(&b.0).unwrap())
        .chunk_by(|entry| entry.0)
        .into_iter()
        .map(|(x, group)| {
            let group_vec: Vec<_> = group.collect();
            let preprocess = data_point(
                &group_vec
                    .iter()
                    .map(|(_, t, _, _)| *t)
                    .collect::<Vec<f32>>(),
            );
            let online = data_point(
                &group_vec
                    .iter()
                    .map(|(_, _, t, _)| *t)
                    .collect::<Vec<f32>>(),
            );
            let total = data_point(
                &group_vec
                    .iter()
                    .map(|(_, _, _, t)| *t)
                    .collect::<Vec<f32>>(),
            );
            (
                x,
                Points {
                    preprocess,
                    online,
                    total,
                },
            )
        })
        .collect();

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

    chart = add_mean_series(chart, &stats, "Preprocess Mean", |p| p.preprocess.mean);
    chart = add_mean_series(chart, &stats, "Online Mean", |p| p.online.mean);
    chart = add_mean_series(chart, &stats, "Total Mean", |p| p.total.mean);

    if show_min_max {
        chart = add_min_max_band(
            chart,
            &stats,
            "Preprocess Min/Max",
            |p| &p.preprocess,
            "#ccc",
        );
        chart = add_min_max_band(chart, &stats, "Online Min/Max", |p| &p.online, "#ccc");
        chart = add_min_max_band(chart, &stats, "Total Min/Max", |p| &p.total, "#ccc");
    }
    // Save the chart as HTML file.
    HtmlRenderer::new(title, 1000, 800)
        .theme(THEME)
        .save(&chart, output_file)
        .unwrap();

    Ok(chart)
}

fn add_mean_series(
    chart: Chart,
    stats: &[(f32, Points)],
    name: &str,
    extract: impl Fn(&Points) -> f32,
) -> Chart {
    chart.series(
        Line::new()
            .name(name)
            .data(
                stats
                    .iter()
                    .map(|(x, points)| vec![*x, extract(points)])
                    .collect(),
            )
            .symbol_size(6),
    )
}

fn add_min_max_band(
    chart: Chart,
    stats: &[(f32, Points)],
    name: &str,
    extract: impl Fn(&Points) -> &DataPoint,
    color: &str,
) -> Chart {
    chart.series(
        Line::new()
            .name(name)
            .data(
                stats
                    .iter()
                    .map(|(x, points)| vec![*x, extract(points).max])
                    .chain(
                        stats
                            .iter()
                            .rev()
                            .map(|(x, points)| vec![*x, extract(points).min]),
                    )
                    .collect(),
            )
            .show_symbol(false)
            .line_style(LineStyle::new().opacity(0.0))
            .area_style(AreaStyle::new().opacity(0.3).color(color)),
    )
}
