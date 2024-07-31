use charming::{
    component::{
        Axis, DataView, Feature, Legend, Restore, SaveAsImage, Title, Toolbox, ToolboxDataZoom,
    },
    element::{NameLocation, Orient, Tooltip, Trigger},
    series::{Line, Scatter},
    theme::Theme,
    Chart, HtmlRenderer,
};
use tlsn_benches::metrics::Metrics;

const THEME: Theme = Theme::Default;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let csv_file = std::env::args()
        .nth(1)
        .expect("Usage: plot <path_to_csv_file>");

    let mut rdr = csv::Reader::from_path(csv_file)?;

    // Prepare data for plotting
    let all_data: Vec<Metrics> = rdr
        .deserialize::<Metrics>()
        .collect::<Result<Vec<_>, _>>()?; // Attempt to collect all results, return an error if any fail

    let _chart = runtime_vs_latency(&all_data)?;
    let _chart = runtime_vs_bandwidth(&all_data)?;

    Ok(())
}

fn runtime_vs_latency(all_data: &[Metrics]) -> Result<Chart, Box<dyn std::error::Error>> {
    const TITLE: &str = "Runtime vs Latency";

    let data: Vec<Vec<f32>> = all_data
        .iter()
        .filter(|record| record.name == "latency")
        .map(|record| {
            let total_delay = record.upload_delay + record.download_delay; // Calculate the sum of upload and download delays.
            vec![total_delay as f32, record.runtime as f32]
        })
        .collect();

    // https://github.com/yuankunzhang/charming
    let chart = Chart::new()
        .title(Title::new().text(TITLE))
        .tooltip(Tooltip::new().trigger(Trigger::Axis))
        .legend(Legend::new().orient(Orient::Vertical))
        .toolbox(
            Toolbox::new().show(true).feature(
                Feature::new()
                    .save_as_image(SaveAsImage::new())
                    .restore(Restore::new())
                    .data_zoom(ToolboxDataZoom::new().y_axis_index("none"))
                    .data_view(DataView::new().read_only(false)),
            ),
        )
        .x_axis(
            Axis::new()
                .scale(true)
                .name("Upload + Download Latency (ms)")
                .name_location(NameLocation::Center),
        )
        .y_axis(
            Axis::new()
                .scale(true)
                .name("Runtime (s)")
                .name_location(NameLocation::Middle),
        )
        .series(
            Scatter::new()
                .name("Combined Latency")
                .symbol_size(10)
                .data(data),
        );

    // Save the chart as HTML file.
    HtmlRenderer::new(TITLE, 1000, 800)
        .theme(THEME)
        .save(&chart, "runtime_vs_latency.html")
        .unwrap();

    Ok(chart)
}

fn runtime_vs_bandwidth(all_data: &[Metrics]) -> Result<Chart, Box<dyn std::error::Error>> {
    const TITLE: &str = "Runtime vs Bandwidth";

    let download_data: Vec<Vec<f32>> = all_data
        .iter()
        .filter(|record| record.name == "download_bandwidth")
        .map(|record| vec![record.download as f32, record.runtime as f32])
        .collect();
    let upload_deferred_data: Vec<Vec<f32>> = all_data
        .iter()
        .filter(|record| record.name == "upload_bandwidth" && record.defer_decryption)
        .map(|record| vec![record.upload as f32, record.runtime as f32])
        .collect();
    let upload_non_deferred_data: Vec<Vec<f32>> = all_data
        .iter()
        .filter(|record| record.name == "upload_bandwidth" && !record.defer_decryption)
        .map(|record| vec![record.upload as f32, record.runtime as f32])
        .collect();

    // https://github.com/yuankunzhang/charming
    let chart = Chart::new()
        .title(Title::new().text(TITLE))
        .tooltip(Tooltip::new().trigger(Trigger::Axis))
        .legend(Legend::new().orient(Orient::Vertical))
        .toolbox(
            Toolbox::new().show(true).feature(
                Feature::new()
                    .save_as_image(SaveAsImage::new())
                    .restore(Restore::new())
                    .data_zoom(ToolboxDataZoom::new().y_axis_index("none"))
                    .data_view(DataView::new().read_only(false)),
            ),
        )
        .x_axis(
            Axis::new()
                .scale(true)
                .name("Bandwidth (Mbps)")
                .name_location(NameLocation::Center),
        )
        .y_axis(
            Axis::new()
                .scale(true)
                .name("Runtime (s)")
                .name_location(NameLocation::Middle),
        )
        .series(
            Line::new()
                .name("Download bandwidth")
                .symbol_size(10)
                .data(download_data),
        )
        .series(
            Line::new()
                .name("Upload bandwidth (deferred decryption)")
                .symbol_size(10)
                .data(upload_deferred_data),
        )
        .series(
            Line::new()
                .name("Upload bandwidth")
                .symbol_size(10)
                .data(upload_non_deferred_data),
        );
    // Save the chart as HTML file.
    HtmlRenderer::new(TITLE, 1000, 800)
        .theme(THEME)
        .save(&chart, "runtime_vs_bandwidth.html")
        .unwrap();

    Ok(chart)
}
