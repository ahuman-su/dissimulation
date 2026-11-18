use crate::runtime::{self, AppState, LifecycleState};
use dissimulation_core::{ExposureLevel, MacMode, NetworkSnapshot};
use tauri::{
    AppHandle, Emitter, Manager, Wry,
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

const TRAY_ID: &str = "dissimulation-status";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneralStatus {
    NoAlert,
    Warning,
    Important,
    Unavailable,
}

pub struct TraySummaryItems {
    pub exposure: MenuItem<Wry>,
    pub firewall: MenuItem<Wry>,
    pub mac: MenuItem<Wry>,
    pub factual_status: MenuItem<Wry>,
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(
        app,
        "open-dashboard",
        "Ouvrir le tableau de bord",
        true,
        None::<&str>,
    )?;
    let refresh = MenuItem::with_id(
        app,
        "refresh-analysis",
        "Actualiser l'analyse réseau",
        true,
        None::<&str>,
    )?;
    let factual_status = MenuItem::with_id(
        app,
        "factual-status",
        "Initialisation de l'analyse…",
        false,
        None::<&str>,
    )?;
    let exposure = MenuItem::with_id(
        app,
        "exposure-summary",
        "Ports potentiellement exposés : analyse en cours",
        false,
        None::<&str>,
    )?;
    let firewall = MenuItem::with_id(
        app,
        "firewall-summary",
        "Pare-feu UFW : analyse en cours",
        false,
        None::<&str>,
    )?;
    let mac = MenuItem::with_id(
        app,
        "mac-summary",
        "Randomisation MAC : analyse en cours",
        false,
        None::<&str>,
    )?;
    let profile = MenuItem::with_id(
        app,
        "activate-profile",
        "Activer un profil de sécurité…",
        true,
        None::<&str>,
    )?;
    let settings = MenuItem::with_id(app, "open-settings", "Paramètres", true, None::<&str>)?;
    let quit = MenuItem::with_id(
        app,
        "quit-completely",
        "Quitter complètement",
        true,
        None::<&str>,
    )?;
    let separator_1 = PredefinedMenuItem::separator(app)?;
    let separator_2 = PredefinedMenuItem::separator(app)?;
    let separator_3 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[
            &open,
            &refresh,
            &separator_1,
            &factual_status,
            &exposure,
            &firewall,
            &mac,
            &separator_2,
            &profile,
            &settings,
            &separator_3,
            &quit,
        ],
    )?;

    let initial_icon = status_icon(GeneralStatus::Unavailable);
    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .icon(initial_icon)
        .tooltip("Dissimulation — analyse en cours d'initialisation")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open-dashboard" => show_page(app, "dashboard"),
            "refresh-analysis" => {
                let app = app.clone();
                let _ = std::thread::Builder::new()
                    .name("dissimulation-manual-scan".to_string())
                    .spawn(move || {
                        runtime::scan(&app);
                    });
            }
            "activate-profile" => show_page(app, "profiles"),
            "open-settings" => show_page(app, "settings"),
            "quit-completely" => quit_completely(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    if let Some(state) = app.try_state::<AppState>() {
        *state
            .tray_items
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(TraySummaryItems {
            exposure,
            firewall,
            mac,
            factual_status,
        });
    }
    Ok(())
}

pub fn update(app: &AppHandle, snapshot: &NetworkSnapshot) {
    let status = runtime::tray_status(snapshot);
    let exposed = snapshot
        .ports
        .iter()
        .filter(|port| {
            matches!(
                port.exposure,
                ExposureLevel::AllInterfaces | ExposureLevel::SpecificInterface
            )
        })
        .count();
    let firewall = match snapshot.firewall.enabled {
        Some(true) => "actif",
        Some(false) => "désactivé",
        None => "indéterminé",
    };
    let eligible_interfaces = snapshot
        .interfaces
        .iter()
        .filter(|interface| interface.eligible_for_randomization)
        .count();
    let randomized_interfaces = snapshot
        .interfaces
        .iter()
        .filter(|interface| {
            interface.eligible_for_randomization
                && matches!(interface.mac_mode, MacMode::Random | MacMode::Stable)
        })
        .count();
    let tooltip = factual_tooltip(status, exposed);

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_icon(Some(status_icon(status)));
        let _ = tray.set_tooltip(Some(&tooltip));
    }

    if let Some(state) = app.try_state::<AppState>() {
        if let Some(items) = state
            .tray_items
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
        {
            let _ = items.factual_status.set_text(tooltip);
            let _ = items
                .exposure
                .set_text(format!("Ports potentiellement exposés : {exposed}"));
            let _ = items
                .firewall
                .set_text(format!("Pare-feu UFW : {firewall}"));
            let _ = items.mac.set_text(if eligible_interfaces == 0 {
                "Randomisation MAC : aucune interface éligible".to_string()
            } else {
                format!(
                    "MAC pseudonymisée : {randomized_interfaces}/{eligible_interfaces} interface{}",
                    if eligible_interfaces > 1 { "s" } else { "" }
                )
            });
        }
    }
}

fn factual_tooltip(status: GeneralStatus, exposed: usize) -> String {
    match status {
        GeneralStatus::Unavailable => "Dissimulation — analyse indisponible".to_string(),
        GeneralStatus::Important => "Dissimulation — alerte importante détectée".to_string(),
        GeneralStatus::Warning => format!(
            "Dissimulation — {exposed} port{} potentiellement exposé{}",
            if exposed > 1 { "s" } else { "" },
            if exposed > 1 { "s" } else { "" }
        ),
        GeneralStatus::NoAlert => "Dissimulation — aucune alerte détectée".to_string(),
    }
}

fn status_icon(status: GeneralStatus) -> Image<'static> {
    let color = match status {
        GeneralStatus::NoAlert => [52, 211, 153, 255],
        GeneralStatus::Warning => [245, 158, 11, 255],
        GeneralStatus::Important => [239, 68, 68, 255],
        GeneralStatus::Unavailable => [148, 163, 184, 255],
    };
    let size = 32_u32;
    let mut pixels = vec![0_u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - 15.5;
            let dy = y as f32 - 15.5;
            let distance = (dx * dx + dy * dy).sqrt();
            if distance <= 13.5 {
                let offset = ((y * size + x) * 4) as usize;
                let pixel = if distance >= 11.5 {
                    [238, 242, 247, 255]
                } else {
                    color
                };
                pixels[offset..offset + 4].copy_from_slice(&pixel);
            }
        }
    }
    Image::new_owned(pixels, size, size)
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        runtime::set_lifecycle(app, LifecycleState::InterfaceOpen);
    }
}

pub fn hide_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
        runtime::set_lifecycle(app, LifecycleState::InterfaceHidden);
    }
}

pub fn toggle_main_window(app: &AppHandle) {
    let is_visible = app
        .get_webview_window("main")
        .and_then(|window| window.is_visible().ok())
        .unwrap_or(false);
    if is_visible {
        hide_main_window(app);
    } else {
        show_main_window(app);
    }
}

fn show_page(app: &AppHandle, page: &str) {
    show_main_window(app);
    let _ = app.emit("navigate", page);
}

pub fn quit_completely(app: &AppHandle) {
    if let Some(state) = app.try_state::<AppState>() {
        state.request_quit();
    }
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("dissimulation-shutdown".to_string())
        .spawn(move || {
            runtime::shutdown(&app);
            app.exit(0);
        });
}
