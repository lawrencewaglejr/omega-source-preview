# Offline AI image inputs

The image pins the working appliance's Ollama 0.33.3 arm64 CPU runtime and
`qwen3:1.7b` model. The authoritative build inventory is
[`image/locks/ai.manifest.json`](../image/locks/ai.manifest.json).

The public [Ollama v0.33.3 release API](https://api.github.com/repos/ollama/ollama/releases/tags/v0.33.3)
reported the arm64 archive as 1,554,076,220 bytes with SHA-256
`4425a112af999ae6572c1ce211fbabeaca7bab23ed5860972acdfc0cc2358420`.
The retrieved [model registry manifest](https://registry.ollama.ai/v2/library/qwen3/manifests/1.7b)
is 859 bytes with SHA-256
`8f68893c685c3ddff2aa3fffce2aa60a30bb2da65ca488b61fff134a4d1730e7`.
Its five references match the installed appliance's independently hashed blobs.
These hashes identify the exact reviewed inputs; they do not substitute for a
publisher signature or a model-quality assessment.

The selected archive members include the CLI, CPU backends, shared libraries,
required library symlinks, and bundled third-party license files. Individual
hashes were measured from the working installed runtime and must also match
the verified release archive during image staging. CUDA directories are not
included. The separately pinned [Ollama license](https://raw.githubusercontent.com/ollama/ollama/v0.33.3/LICENSE)
is installed beside the runtime; the model's license is retained as its
referenced model blob.

Eight content-addressed cache objects are required: runtime archive, runtime
license, model manifest, and five model blobs. The stager never executes the
cached runtime or downloads anything. It rejects altered objects, unsafe cache
file metadata, inconsistent model references, duplicate selected archive
members, unsupported member types, and links outside the selected runtime.
Output is prepared in a private temporary directory and published only after
all checks pass. A preexisting output is preserved.

The generated release includes the AI inventory and its hash in provenance,
and separate runtime/model entries in the software bill of materials. Runtime
files are public application files; model state is owned by the non-login
`omega-ai` service account with private directory/file permissions. Runtime
keys, prompts, responses, downloaded reports, credentials, and telemetry from
the development appliance are not image inputs.

Cache verification and successful staging are packaging checks. Fresh-card
boot, sustained telemetry collection, actual inference/report generation,
resource use, and release reproducibility still require separate evidence.
