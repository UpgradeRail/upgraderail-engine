# UpgradeRail action

Check out the engine and contracts inputs, then use this composite action with a configuration path and optional JSON report path. Static analysis always runs without runtime scenarios. Set `run-simulations: "true"` only in trusted workflows where required RPC and source-account credentials are available. Do not enable it for fork pull requests that cannot safely receive protected credentials. The action requests no write permissions and does not post comments.
