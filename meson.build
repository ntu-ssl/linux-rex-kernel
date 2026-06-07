make = find_program('make')
nproc = find_program('nproc')
cpu_count = run_command(
  nproc,
  capture: true,
  check: true
).stdout().strip()

# 'cp', '@SOURCE_ROOT@/scripts/q-script/.config', '@OUTPUT@'
# 'cp', '@SOURCE_ROOT@/scripts/q-script/.config', '@SOURCE_ROOT@/linux/.config'
kernel_config = custom_target(
  'kernel-config',
  output: ['.config'],
  command: [
    'cp', '@SOURCE_ROOT@/scripts/q-script/.rust_available_and_allow_notrace_config', '@SOURCE_ROOT@/build/linux/.config'
  ],
  console: true,
  build_by_default: false
)

kbuild_dir = meson.current_build_dir()

kernel_build = custom_target(
  'kernel-build',
  output: ['vmlinux'],
  command: [
    'make', '-C','@SOURCE_ROOT@/linux', '-kj', cpu_count, 'O=' + kbuild_dir
  ],
  env: ['LLVM=1'],
  console: true,
  depends: kernel_config,
  build_always_stale: true,
  build_by_default: false
)

kernel_libbpf = custom_target(
  'kernel-libbpf',
  output: ['libbpf.so', 'bpf_helper_defs.h'],
  command: [
    make, '-C', '@SOURCE_ROOT@/linux/tools/lib/bpf/', '-kj', cpu_count, 'O=' + kbuild_dir
  ],
  env: ['LLVM=1'],
  console: true,
  depends: kernel_build,
  build_by_default: true
)

subdir('usr')
subdir('tools')

kernel_dep = declare_dependency(
  include_directories: kernel_usr_inc
)

libbpf_dep = declare_dependency(
  link_with: kernel_libbpf[0],
  include_directories: kernel_toolslib_inc,
  sources: kernel_libbpf[1]
)
