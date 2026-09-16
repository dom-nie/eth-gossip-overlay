//! Reloads driven the way an operator drives them: `SIGHUP` against the real binary, with the
//! report read back out of the log line every reload writes.

use nix::sys::signal::Signal;

mod common;

use common::Fixture;

/// `docs/security.md`, rotation step 1, on a host where the key reaches `config.yaml` before the
/// seed file reaches disk. The first reload fails and says so; the second, with the file in
/// place, applies the key. The runbook's "check the report says it applied" has to be true on
/// the reload the operator runs after fixing the file, not only on a host that never failed.
#[test]
fn seed_rotation_step_one_survives_a_key_that_lands_before_its_file() {
    let fixture = Fixture::new();
    let sidecar = fixture.run();
    sidecar.wait_for(r#""message":"ready""#);
    let previous = fixture.dir.path().join("seed.previous");
    let config = std::fs::read_to_string(&fixture.config).unwrap();
    std::fs::write(
        &fixture.config,
        config.replacen(
            "overlay:\n",
            &format!(
                "overlay:\n  fleet_seed_previous_file: {}\n",
                previous.display()
            ),
            1,
        ),
    )
    .unwrap();

    sidecar.signal(Signal::SIGHUP);
    let failed = sidecar.wait_for("previous values kept");
    assert!(failed.contains("seed.previous"), "{failed}");

    std::fs::write(&previous, format!("{}\n", "cd".repeat(32))).unwrap();
    sidecar.signal(Signal::SIGHUP);
    let reloaded = sidecar.wait_for(r#""message":"reloaded""#);

    assert_eq!(
        common::field(&reloaded, "applied"),
        "overlay.fleet_seed_previous_file",
        "{reloaded}"
    );
}
