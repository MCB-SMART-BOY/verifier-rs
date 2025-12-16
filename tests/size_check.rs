use std::mem::size_of;

#[test]
fn print_sizes() {
    println!("\n=== Structure Sizes ===");
    println!("BpfRegState: {} bytes", size_of::<bpf_verifier::state::reg_state::BpfRegState>());
    println!("BpfFuncState: {} bytes", size_of::<bpf_verifier::state::verifier_state::BpfFuncState>());
    println!("BpfVerifierState: {} bytes", size_of::<bpf_verifier::state::verifier_state::BpfVerifierState>());
    println!("StateCache: {} bytes", size_of::<bpf_verifier::analysis::prune::StateCache>());
    println!("SccTracker: {} bytes", size_of::<bpf_verifier::analysis::prune::SccTracker>());
    println!("JmpHistory: {} bytes", size_of::<bpf_verifier::analysis::prune::JmpHistory>());
    println!("KfuncRegistry: {} bytes", size_of::<bpf_verifier::check::kfunc::KfuncRegistry>());
    println!("VerifierEnv: {} bytes", size_of::<bpf_verifier::verifier::VerifierEnv>());
    println!("MainVerifier: {} bytes", size_of::<bpf_verifier::verifier::MainVerifier>());
    println!("ExceptionState: {} bytes", size_of::<bpf_verifier::special::exception::ExceptionState>());
    println!("CallbackState: {} bytes", size_of::<bpf_verifier::check::callback::CallbackState>());
    println!("MayGotoState: {} bytes", size_of::<bpf_verifier::check::jump::MayGotoState>());
}
