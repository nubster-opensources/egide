fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(
            std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("egide_descriptor.bin"),
        )
        .compile_protos(
            &[
                "proto/egide/v1/sys.proto",
                "proto/egide/v1/secrets.proto",
                "proto/egide/v1/transit.proto",
                "proto/egide/v1/auth.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
