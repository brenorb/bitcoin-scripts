use bitcoin::consensus::encode::serialize;
use bitcoin::script::Instruction;
use bitcoin::Witness;
use bitcoin_lab::commitments::{
    ternary_hash_path_integer_commitment, ternary_hash_path_integer_witness,
    verify_ternary_hash_path_to_integer,
};
use bitcoin_lab::support::execution::execute_script_with_inputs_strict;
use bitcoin_lab::support::script::ScriptCompilation;

fn main() {
    let preimage = [0x42; 32];
    let value = 0x1234_5678;
    let commitment = ternary_hash_path_integer_commitment(&preimage, value, 31);
    let witness = ternary_hash_path_integer_witness(&preimage, value, 31);
    let verifier = verify_ternary_hash_path_to_integer(31, commitment);
    let execution = execute_script_with_inputs_strict(verifier.clone(), witness.clone());
    assert!(execution.success, "benchmark fixture failed: {execution}");
    let compiled = verifier.compile_with_policy();
    let script_bytes = compiled.len();
    let instructions = compiled
        .instructions()
        .map(|instruction| instruction.expect("generated script must parse"))
        .collect::<Vec<_>>();
    let static_non_push_opcodes = instructions
        .iter()
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count();

    println!("primitive=ternary_hash_path_integer");
    println!("bit_width=31");
    println!("trit_count=20");
    println!("script_bytes={script_bytes}");
    println!(
        "witness_bytes={}",
        serialize(&Witness::from_slice(&witness)).len()
    );
    println!("witness_items={}", witness.len());
    println!("hint_items=0");
    println!("stack_peak={}", execution.stats.max_nb_stack_items);
    println!("static_instructions={}", instructions.len());
    println!("static_non_push_opcodes={static_non_push_opcodes}");
    // In tapscript the pinned interpreter's `opcode_count` counts every
    // instruction position, executed or not (OP_CODESEPARATOR positions), so
    // it is not an executed-opcode measurement.
    println!(
        "interpreter_tapscript_position_count={}",
        execution.stats.opcode_count
    );
    println!("executed_opcodes=unavailable");
    println!("execution_class=unclassified");
    println!("commitment_bytes={}", commitment.len());
}
