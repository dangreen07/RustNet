use iced::Subscription;
use rust_net::gui::State;

fn main() -> iced::Result {
    iced::application("RustNet Manager", State::update, State::view)
        .subscription(|state| {
            Subscription::batch(vec![
                state.time_subscription(),
                state.networking_subscription(),
            ])
        })
        .run()
}
