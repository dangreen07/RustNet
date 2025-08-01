use iced::Subscription;
use rust_net::gui::State;

/// The main entry point for the RustNet application.
///
/// This function initializes and runs the Iced-based graphical user interface.
/// It sets up the application's state, view, and update logic, along with
/// subscriptions for handling asynchronous events like timers and networking.
fn main() -> iced::Result {
    iced::application("RustNet Manager", State::update, State::view)
        .subscription(|state| {
            // The application combines multiple subscriptions into one.
            // - `time_subscription` is used for UI animations (e.g., feedback messages).
            // - `networking_subscription` manages all peer-to-peer network interactions.
            Subscription::batch(vec![
                state.time_subscription(),
                state.networking_subscription(),
            ])
        })
        .run()
}
