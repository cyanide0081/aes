package main

import "core:fmt"
import "core:os"
import "core:mem"
import "core:mem/virtual"

import "aes"
import "arguments"
import "usage"

main :: proc() {
	// NOTE: overriding the default heap allocator because we
	// don't free any memory anyways
	arena := virtual.Arena{}
	arena_err := virtual.arena_init_growing(&arena)
	ensure(arena_err == nil)
	context.allocator = virtual.arena_allocator(&arena)

	args, _ := arguments.parse(os.args[1:])
	fmt.println("arguments:", args)
	if !arguments.state_is_valid(&args) {
		usage.print()
		return
	}

	bufs, load_err := load_data_and_prep_bufs(args.input)
	if load_err != nil {
		fmt.eprintln("Could not open file:", os.error_string(load_err))
		return
	}

	aes.process(&args, &bufs)
	fmt.println("processed:", bufs.output)


	// TODO: write output
}

PADDING :: 16

load_data_and_prep_bufs :: proc(filename: string) -> (bufs: aes.Buffers, err: os.Error) {
	file := os.open(filename) or_return

	alloc := context.allocator
	file_size := int(os.file_size(file) or_return)

	buf_size := mem.align_formula(file_size, PADDING)
	if buf_size - file_size == 0 {
		buf_size += PADDING // always add padding, even when already aligned
	}

	buf := make([]u8, buf_size * 2)
	os.read(file, buf) or_return

	// NOTE: PKCS#7 padding
	pad := buf_size - file_size
	mem.set(raw_data(buf[file_size:]), u8(pad), pad)

	bufs.input = buf[:buf_size]
	bufs.output = buf[buf_size:]
	return bufs, nil
}
