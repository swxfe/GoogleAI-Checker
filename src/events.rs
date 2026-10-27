use tokio::sync::mpsc::{UnboundedSender, error::SendError};

/// Background results wake the native event loop instead of waiting for polling.
pub struct EventSender<T> {
    sender: UnboundedSender<T>,
    context: Option<egui::Context>,
}
impl<T> EventSender<T> {
    pub fn with_ui(sender: UnboundedSender<T>, context: egui::Context) -> Self {
        Self {
            sender,
            context: Some(context),
        }
    }
    pub fn send(&self, event: T) -> Result<(), SendError<T>> {
        self.sender.send(event)?;
        if let Some(context) = &self.context {
            context.request_repaint();
        }
        Ok(())
    }
}
impl<T> Clone for EventSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            context: self.context.clone(),
        }
    }
}
impl<T> From<UnboundedSender<T>> for EventSender<T> {
    fn from(sender: UnboundedSender<T>) -> Self {
        Self {
            sender,
            context: None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn events_wake_the_ui_after_queueing_and_preserve_order() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let context = egui::Context::default();
        for _ in 0..2 {
            let _ = context.run(egui::RawInput::default(), |_| {});
        }
        let wakes = Arc::new(AtomicUsize::new(0));
        let count = wakes.clone();
        context.set_request_repaint_callback(move |_| {
            count.fetch_add(1, Ordering::Relaxed);
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let tx = EventSender::with_ui(tx, context);
        tx.send(1).unwrap();
        tx.clone().send(2).unwrap();
        assert_eq!(rx.try_recv().unwrap(), 1);
        assert_eq!(rx.try_recv().unwrap(), 2);
        assert!(wakes.load(Ordering::Relaxed) > 0);
        drop(rx);
        assert!(tx.send(3).is_err());
    }
}
