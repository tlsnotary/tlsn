use std::f32;

use charming::{
    Chart, HtmlRenderer, ImageRenderer,
    component::{Axis, Legend, Title},
    element::{
        AreaStyle, ItemStyle, LineStyle, LineStyleType, NameLocation, Orient, TextStyle, Tooltip,
        Trigger,
    },
    series::Line,
    theme::Theme,
};
use clap::Parser;
use harness_core::bench::BenchItems;
use polars::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Path to the Bench.toml file with benchmark spec
    toml: String,

    /// Paths to CSV files with benchmark results (one or more)
    csv: Vec<String>,

    /// Labels for each dataset (optional, defaults to "Dataset 1", "Dataset 2", etc.)
    #[arg(short, long, num_args = 0..)]
    labels: Vec<String>,

    /// Add min/max bands to plots
    #[arg(long, default_value_t = false)]
    min_max_band: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.csv.is_empty() {
        return Err("At least one CSV file must be provided".into());
    }

    // Generate labels if not provided
    let labels: Vec<String> = if cli.labels.is_empty() {
        cli.csv
            .iter()
            .enumerate()
            .map(|(i, _)| format!("Dataset {}", i + 1))
            .collect()
    } else if cli.labels.len() != cli.csv.len() {
        return Err(format!(
            "Number of labels ({}) must match number of CSV files ({})",
            cli.labels.len(),
            cli.csv.len()
        )
        .into());
    } else {
        cli.labels.clone()
    };

    // Load all CSVs and add dataset label
    let mut dfs = Vec::new();
    for (csv_path, label) in cli.csv.iter().zip(labels.iter()) {
        let mut df = CsvReadOptions::default()
            .try_into_reader_with_file_path(Some(csv_path.clone().into()))?
            .finish()?;

        let label_series = Series::new("dataset_label".into(), vec![label.as_str(); df.height()]);
        df.with_column(label_series)?;
        dfs.push(df);
    }

    // Combine all dataframes
    let df = dfs
        .into_iter()
        .reduce(|acc, df| acc.vstack(&df).unwrap())
        .unwrap();

    let items: BenchItems = toml::from_str(&std::fs::read_to_string(&cli.toml)?)?;
    let groups = items.group;

    for group in groups {
        // Determine which field varies in benches for this group
        let benches_in_group: Vec<_> = items
            .bench
            .iter()
            .filter(|b| b.group.as_deref() == Some(&group.name))
            .collect();

        if benches_in_group.is_empty() {
            continue;
        }

        // Check which field has varying values
        let bandwidth_varies = benches_in_group
            .windows(2)
            .any(|w| w[0].bandwidth != w[1].bandwidth);
        let latency_varies = benches_in_group
            .windows(2)
            .any(|w| w[0].protocol_latency != w[1].protocol_latency);
        let download_size_varies = benches_in_group
            .windows(2)
            .any(|w| w[0].download_size != w[1].download_size);

        if download_size_varies {
            let upload_size = group.upload_size.unwrap_or(1024);
            plot_runtime_vs(
                &df,
                &labels,
                cli.min_max_band,
                &group.name,
                "download_size",
                1.0 / 1024.0, // bytes to KB
                "Runtime vs Response Size",
                format!("{} bytes upload size", upload_size),
                "runtime_vs_download_size",
                "Response Size (KB)",
                true, // legend on left
            )?;
        } else if bandwidth_varies {
            let latency = group.protocol_latency.unwrap_or(50);
            plot_runtime_vs(
                &df,
                &labels,
                cli.min_max_band,
                &group.name,
                "bandwidth",
                1.0 / 1000.0, // Kbps to Mbps
                "Runtime vs Bandwidth",
                format!("{} ms Latency", latency),
                "runtime_vs_bandwidth",
                "Bandwidth (Mbps)",
                false, // legend on right
            )?;
        } else if latency_varies {
            let bandwidth = group.bandwidth.unwrap_or(1000);
            plot_runtime_vs(
                &df,
                &labels,
                cli.min_max_band,
                &group.name,
                "latency",
                1.0,
                "Runtime vs Latency",
                format!("{} bps bandwidth", bandwidth),
                "runtime_vs_latency",
                "Latency (ms)",
                true, // legend on left
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn plot_runtime_vs(
    df: &DataFrame,
    labels: &[String],
    show_min_max: bool,
    group: &str,
    x_col: &str,
    x_scale: f32,
    title: &str,
    subtitle: String,
    output_file: &str,
    x_axis_label: &str,
    legend_left: bool,
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
        .group_by([col("x"), col("dataset_label")])
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
        .sort(["dataset_label", "x"], Default::default())
        .collect()?;

    // Build legend entries
    let mut legend_data = Vec::new();
    for label in labels {
        legend_data.push(format!("Total Mean ({})", label));
        legend_data.push(format!("Online Mean ({})", label));
    }

    let mut chart = Chart::new()
        .title(
            Title::new()
                .text(title)
                .left("center")
                .subtext(subtitle)
                .subtext_style(TextStyle::new().font_size(16)),
        )
        .tooltip(Tooltip::new().trigger(Trigger::Axis))
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

    // Add legend with conditional positioning
    let legend = Legend::new()
        .data(legend_data)
        .top("80")
        .orient(Orient::Vertical)
        .item_gap(10);

    let legend = if legend_left {
        legend.left("110")
    } else {
        legend.right("110")
    };

    chart = chart.legend(legend);

    // Define colors for each dataset
    let colors = vec![
        "#5470c6", "#91cc75", "#fac858", "#ee6666", "#73c0de", "#3ba272", "#fc8452", "#9a60b4",
    ];

    for (idx, label) in labels.iter().enumerate() {
        let color = colors.get(idx % colors.len()).unwrap();

        // Total time - solid line
        chart = add_dataset_series(
            &chart,
            &stats_df,
            label,
            &format!("Total Mean ({})", label),
            "total_mean",
            false,
            color,
        )?;

        // Online time - dashed line (same color as total)
        chart = add_dataset_series(
            &chart,
            &stats_df,
            label,
            &format!("Online Mean ({})", label),
            "online_mean",
            true,
            color,
        )?;

        if show_min_max {
            chart = add_dataset_min_max_band(
                &chart,
                &stats_df,
                label,
                &format!("Total Min/Max ({})", label),
                "total",
                color,
            )?;
        }
    }
    // Save the chart as HTML file (no theme)
    HtmlRenderer::new(title, 1000, 800)
        .save(&chart, &format!("{}.html", output_file))
        .unwrap();

    // Save SVG with default theme
    ImageRenderer::new(1000, 800)
        .theme(Theme::Default)
        .save(&chart, &format!("{}.svg", output_file))
        .unwrap();

    // Save SVG with dark theme
    ImageRenderer::new(1000, 800)
        .theme(Theme::Dark)
        .save(&chart, &format!("{}_dark.svg", output_file))
        .unwrap();

    Ok(chart)
}

fn add_dataset_series(
    chart: &Chart,
    df: &DataFrame,
    dataset_label: &str,
    series_name: &str,
    col_name: &str,
    dashed: bool,
    color: &str,
) -> Result<Chart, Box<dyn std::error::Error>> {
    // Filter for specific dataset
    let mask = df.column("dataset_label")?.str()?.equal(dataset_label);
    let filtered = df.filter(&mask)?;

    let x = filtered.column("x")?.f32()?;
    let y = filtered.column(col_name)?.f32()?;

    let data: Vec<Vec<f32>> = x
        .into_iter()
        .zip(y.into_iter())
        .filter_map(|(x, y)| Some(vec![x?, y?]))
        .collect();

    let mut line = Line::new()
        .name(series_name)
        .data(data)
        .symbol_size(6)
        .item_style(ItemStyle::new().color(color));

    let mut line_style = LineStyle::new();
    if dashed {
        line_style = line_style.type_(LineStyleType::Dashed);
    }
    line = line.line_style(line_style.color(color));

    Ok(chart.clone().series(line))
}

fn add_dataset_min_max_band(
    chart: &Chart,
    df: &DataFrame,
    dataset_label: &str,
    name: &str,
    col_prefix: &str,
    color: &str,
) -> Result<Chart, Box<dyn std::error::Error>> {
    // Filter for specific dataset
    let mask = df.column("dataset_label")?.str()?.equal(dataset_label);
    let filtered = df.filter(&mask)?;

    let x = filtered.column("x")?.f32()?;
    let min_col = filtered.column(&format!("{}_min", col_prefix))?.f32()?;
    let max_col = filtered.column(&format!("{}_max", col_prefix))?.f32()?;

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
