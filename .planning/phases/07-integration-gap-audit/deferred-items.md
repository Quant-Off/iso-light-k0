# Phase 7 Deferred Items

본 파일은 Phase 7 실행 중 발견되었으나 본 phase scope 밖이라 별도 cleanup plan 으로 처리 예정인 항목들을 기록.

## D-PHASE7-001 iso-user-lumen 6 dead deps

**발견 위치**: Plan 04 Task 2 forward leg (`make check-machete`)
**발견 도구**: cargo-machete v0.9.2
**affected file**: `crates/iso-user-lumen/Cargo.toml`
**dead deps** (직접 `use` 호출 부재 `src/main.rs` 기준):
- `zeroize`
- `constant-time`
- `sha2`
- `sha3`
- `postcard`
- `serde`

**격리 처리**: `crates/iso-user-lumen/Cargo.toml` `[package.metadata.cargo-machete]` ignored 리스트로 임시 격리 (per-crate ignore mechanism)

**격리 정당화**: Phase 7 정본 audit scope 는 커널 `Cargo.toml` 만 다룸. sibling user-space crate `iso-user-lumen` 의 dep cleanup 은 본 phase 의 책임 범위 밖. 단 cargo-machete 가 본 finding 을 surface 한 것은 게이트가 의도대로 작동함의 증거 (false negative 부재).

**향후 처리 plan**:
1. 별도 cleanup plan (예 Phase 7.5 또는 v2.0 user-space-cleanup phase) 에서 본 6 deps 의 진정한 dead 여부 재검증
2. 진정 dead 시 `crates/iso-user-lumen/Cargo.toml` `[dependencies]` 블록에서 6 entries 제거 + 본 metadata block 전체 삭제 + cleanup commit
3. 만약 transitive feature 의존 등으로 미래 사용 예정이라면 `# Phase X future use` 정당화 주석 추가 후 metadata block 유지

**미해소 위험**:
- 본 격리는 가시성을 낮추지 않음 (cargo-machete 가 ignored entry 를 명시적으로 인정함)
- 단 ignored 리스트 항목 자체가 향후 plan 에서 review 되지 않으면 supply-chain attack surface 가 indefinite 하게 유지됨
- mitigation: 본 deferred-items.md 의 D-PHASE7-001 가 향후 PROJECT.md 진척 audit 시 strong-fail 사유로 인용 가능
