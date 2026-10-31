//! Event-driven native window with a CPU framebuffer. Repaint deadlines are
//! separate from input wakes so delayed animations never turn into a busy loop.
use anyhow::{Result, anyhow};
use egui_software_backend::{BufferMutRef, ColorFieldOrder, EguiSoftwareRender};
use std::{num::NonZeroU32, sync::Arc, time::Instant};
use winit::{
    application::ApplicationHandler,
    event::{StartCause, WindowEvent},
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop, OwnedDisplayHandle},
    window::{Window, WindowId},
};

pub(crate) fn renderer(order: ColorFieldOrder) -> EguiSoftwareRender {
    // Rectangle conversion in backend 0.0.3 misplaces clipped text meshes.
    // Keep SIMD triangle rendering; avoid cached copies of the framebuffer.
    EguiSoftwareRender::new(order)
        .with_caching(false)
        .with_convert_tris_to_rects(false)
}

pub fn run() -> Result<()> {
    let event_loop = EventLoop::<Repaint>::with_user_event().build()?;
    let context = egui::Context::default();
    let proxy = event_loop.create_proxy();
    context.set_request_repaint_callback(move |request| {
        if let Some(when) = Instant::now().checked_add(request.delay) {
            let _ = proxy.send_event(Repaint {
                when,
                pass: request.current_cumulative_pass_nr,
            });
        }
    });
    let mut desktop = Desktop {
        context,
        state: None,
        deadline: Deadline::default(),
        error: None,
    };
    event_loop.run_app(&mut desktop)?;
    if let Some(error) = desktop.error {
        return Err(anyhow!(error));
    }
    Ok(())
}

struct Repaint {
    when: Instant,
    pass: u64,
}

#[derive(Default)]
struct Deadline(Option<Instant>);
impl Deadline {
    fn schedule(&mut self, when: Instant) {
        self.0 = Some(self.0.map_or(when, |pending| pending.min(when)));
    }
    fn take_due(&mut self, now: Instant) -> bool {
        if self.0.is_some_and(|when| when <= now) {
            self.0 = None;
            true
        } else {
            false
        }
    }
}

struct Desktop {
    context: egui::Context,
    state: Option<WindowState>,
    deadline: Deadline,
    error: Option<String>,
}

struct WindowState {
    app: crate::app::CheckerApp,
    // Clipboard/Wayland state must be destroyed before its display and window.
    input: egui_winit::State,
    surface: softbuffer::Surface<OwnedDisplayHandle, Arc<Window>>,
    _buffer_context: softbuffer::Context<OwnedDisplayHandle>,
    window: Arc<Window>,
    viewport: egui::ViewportInfo,
    renderer: EguiSoftwareRender,
    buffer_size: [u32; 2],
    closing: bool,
}

impl Desktop {
    fn initialize(&mut self, event_loop: &ActiveEventLoop) -> Result<()> {
        let builder = egui::ViewportBuilder::default()
            .with_title("Google AI Checker")
            .with_inner_size([1160.0, 760.0])
            .with_min_inner_size([850.0, 600.0])
            .with_transparent(false);
        let window = Arc::new(egui_winit::create_window(
            &self.context,
            event_loop,
            &builder,
        )?);
        let buffer_context = softbuffer::Context::new(event_loop.owned_display_handle())
            .map_err(|error| anyhow!("Framebuffer context: {error}"))?;
        let surface = softbuffer::Surface::new(&buffer_context, window.clone())
            .map_err(|error| anyhow!("Framebuffer surface: {error}"))?;
        let input = egui_winit::State::new(
            self.context.clone(),
            egui::ViewportId::ROOT,
            window.as_ref(),
            Some(window.scale_factor() as f32),
            None,
            None,
        );
        let mut viewport = egui::ViewportInfo::default();
        egui_winit::update_viewport_info(&mut viewport, &self.context, &window, true);
        self.state = Some(WindowState {
            app: crate::app::CheckerApp::new(&self.context),
            input,
            surface,
            _buffer_context: buffer_context,
            window,
            viewport,
            renderer: renderer(ColorFieldOrder::Bgra),
            buffer_size: [0, 0],
            closing: false,
        });
        self.state.as_ref().unwrap().window.request_redraw();
        Ok(())
    }

    fn fail(&mut self, event_loop: &ActiveEventLoop, error: anyhow::Error) {
        self.error = Some(format!("{error:#}"));
        self.state.take();
        event_loop.exit();
    }
}

impl ApplicationHandler<Repaint> for Desktop {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.state.is_none()
            && let Err(error) = self.initialize(event_loop)
        {
            self.fail(event_loop, error);
        }
    }
    fn suspended(&mut self, _event_loop: &ActiveEventLoop) {
        self.state.take();
    }
    fn user_event(&mut self, _event_loop: &ActiveEventLoop, event: Repaint) {
        if event.pass.saturating_add(1) >= self.context.cumulative_pass_nr() {
            self.deadline.schedule(event.when);
        }
    }
    fn new_events(&mut self, _event_loop: &ActiveEventLoop, cause: StartCause) {
        if matches!(cause, StartCause::ResumeTimeReached { .. })
            && self.deadline.take_due(Instant::now())
            && let Some(state) = &self.state
        {
            state.window.request_redraw();
        }
    }
    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if self.deadline.take_due(Instant::now())
            && let Some(state) = &self.state
        {
            state.window.request_redraw();
        }
        event_loop.set_control_flow(
            self.deadline
                .0
                .map_or(ControlFlow::Wait, ControlFlow::WaitUntil),
        );
    }
    fn window_event(&mut self, event_loop: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        let Some(state) = self.state.as_mut().filter(|state| state.window.id() == id) else {
            return;
        };
        match event {
            WindowEvent::CloseRequested => {
                state.closing = true;
                state.window.request_redraw();
            }
            WindowEvent::RedrawRequested => {
                if let Err(error) = state.draw(&self.context, event_loop) {
                    self.fail(event_loop, error);
                }
            }
            WindowEvent::Destroyed => {
                self.state.take();
                event_loop.exit();
            }
            _ => {
                let response = state.input.on_window_event(&state.window, &event);
                if response.repaint {
                    state.window.request_redraw();
                }
            }
        }
    }
    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        self.state.take();
    }
}

impl WindowState {
    fn draw(&mut self, context: &egui::Context, event_loop: &ActiveEventLoop) -> Result<()> {
        let size = self.window.inner_size();
        let (Some(width), Some(height)) =
            (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
        else {
            return Ok(());
        };
        egui_winit::update_viewport_info(&mut self.viewport, context, &self.window, false);
        let mut input = self.input.take_egui_input(&self.window);
        if self.closing {
            self.viewport.events.push(egui::ViewportEvent::Close);
        }
        input
            .viewports
            .insert(egui::ViewportId::ROOT, self.viewport.clone());
        self.viewport.events.clear();
        let output = context.run_ui(input, |ui| self.app.update(ui));
        self.input
            .handle_platform_output(&self.window, output.platform_output);
        if let Some(viewport) = output.viewport_output.get(&egui::ViewportId::ROOT) {
            let cancelled = viewport
                .commands
                .iter()
                .any(|command| matches!(command, egui::ViewportCommand::CancelClose));
            let close = self.closing
                || viewport
                    .commands
                    .iter()
                    .any(|command| matches!(command, egui::ViewportCommand::Close));
            if close && !cancelled {
                event_loop.exit();
                return Ok(());
            }
            self.closing = false;
            let mut actions = Vec::new();
            egui_winit::process_viewport_commands(
                context,
                &mut self.viewport,
                viewport.commands.clone(),
                &self.window,
                &mut actions,
            );
            for action in actions {
                match action {
                    egui_winit::ActionRequested::Cut => {
                        self.input.egui_input_mut().events.push(egui::Event::Cut)
                    }
                    egui_winit::ActionRequested::Copy => {
                        self.input.egui_input_mut().events.push(egui::Event::Copy)
                    }
                    egui_winit::ActionRequested::Paste => {
                        if let Some(text) = self.input.clipboard_text() {
                            self.input
                                .egui_input_mut()
                                .events
                                .push(egui::Event::Paste(text));
                        }
                    }
                    egui_winit::ActionRequested::Screenshot(_) => {}
                }
            }
        }
        if self.buffer_size != [size.width, size.height] {
            self.surface
                .resize(width, height)
                .map_err(|error| anyhow!("Framebuffer resize: {error}"))?;
            self.buffer_size = [size.width, size.height];
        }
        let primitives = context.tessellate(output.shapes, output.pixels_per_point);
        let mut buffer = self
            .surface
            .buffer_mut()
            .map_err(|error| anyhow!("Framebuffer acquire: {error}"))?;
        buffer.fill(0x001b1b1b);
        self.renderer.render(
            &mut BufferMutRef::new(
                bytemuck::cast_slice_mut(&mut buffer),
                width.get() as usize,
                height.get() as usize,
            ),
            &primitives,
            &output.textures_delta,
            output.pixels_per_point,
        );
        self.window.pre_present_notify();
        buffer
            .present()
            .map_err(|error| anyhow!("Framebuffer present: {error}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn clipped_multilingual_table_matches_the_reference_triangle_rasterizer() {
        let context = egui::Context::default();
        crate::i18n::install_fonts(&context, crate::i18n::Language::Chinese);
        let mut fast = renderer(ColorFieldOrder::Rgba);
        let mut reference = EguiSoftwareRender::new(ColorFieldOrder::Rgba)
            .with_caching(false)
            .with_convert_tris_to_rects(false)
            .with_allow_raster_opt(false);
        let mut actual = vec![[0, 0, 0, 255]; 850 * 400];
        let mut expected = actual.clone();
        for _ in 0..3 {
            let output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(850.0, 400.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    egui::Panel::left("margin")
                        .exact_size(225.0)
                        .show_inside(ui, |_| {});
                    egui::CentralPanel::default().show_inside(ui, |ui| {
                        egui_extras::TableBuilder::new(ui)
                            .column(egui_extras::Column::initial(270.0).clip(true))
                            .column(egui_extras::Column::initial(90.0))
                            .column(egui_extras::Column::remainder())
                            .body(|body| {
                                body.rows(30.0, 8, |mut row| {
                                    row.col(|ui| {
                                        ui.label("Los Angeles #2");
                                    });
                                    row.col(|ui| {
                                        ui.label("VLESS");
                                    });
                                    row.col(|ui| {
                                        ui.label("已保存 可用");
                                    });
                                })
                            });
                    });
                },
            );
            let meshes = context.tessellate(output.shapes, output.pixels_per_point);
            actual.fill([0, 0, 0, 255]);
            expected.fill([0, 0, 0, 255]);
            fast.render(
                &mut BufferMutRef::new(&mut actual, 850, 400),
                &meshes,
                &output.textures_delta,
                output.pixels_per_point,
            );
            reference.render(
                &mut BufferMutRef::new(&mut expected, 850, 400),
                &meshes,
                &output.textures_delta,
                output.pixels_per_point,
            );
        }
        let wrong = actual
            .iter()
            .zip(&expected)
            .filter(|(a, b)| a.iter().zip(b.iter()).any(|(a, b)| a.abs_diff(*b) > 8))
            .count();
        assert!(
            wrong < actual.len() / 500,
            "{wrong} pixels differ from reference"
        );
    }
    #[test]
    fn delayed_repaints_sleep_until_the_earliest_deadline() {
        let now = Instant::now();
        let mut deadline = Deadline::default();
        deadline.schedule(now + Duration::from_secs(1));
        deadline.schedule(now + Duration::from_secs(2));
        assert!(!deadline.take_due(now));
        assert!(!deadline.take_due(now + Duration::from_millis(999)));
        assert!(deadline.take_due(now + Duration::from_secs(1)));
        assert!(!deadline.take_due(now + Duration::from_secs(2)));
        deadline.schedule(now + Duration::from_secs(10));
        deadline.schedule(now);
        assert!(deadline.take_due(now));
    }
}
