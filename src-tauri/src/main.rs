fn main() {
    if std::env::args().nth(1).as_deref() == Some("--privileged-helper") {
        std::process::exit(dissimulation_lib::run_privileged_helper());
    }
    dissimulation_lib::run();
}
