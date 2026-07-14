use eframe::egui;

mod crypto;
mod network;
mod ui;

#[tokio::main]
async fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 650.0])
            .with_resizable(true),
        ..Default::default()
    };

    eframe::run_native(
        "noto-m",
        options,
        Box::new(|cc| {
            ui::configure_styles(&cc.egui_ctx);
            Ok(Box::new(ui::NotoMApp::new()))
        }),
    )
}
