package main

import "core:fmt"
import "core:os"
import "core:mem"
import "core:mem/virtual"

import "aes"
import "arguments"
import "usage"

main :: proc() {
	// NOTE: overriding the default heap allocator since we
	// don't even free any memory
	arena := virtual.Arena{}
	arena_err := virtual.arena_init_growing(&arena)
	ensure(arena_err == nil, "Could not reserve virtual memory")
	context.allocator = virtual.arena_allocator(&arena)

	args := arguments.parse(os.args[1:])
	if !arguments.state_is_valid(&args) {
		usage.print()
		return
	}

	bufs, load_err := load_data(&args)
	if load_err != nil {
		fmt.eprintln("Could not open file:", os.error_string(load_err))
		return
	}

	aes.process(&args, &bufs)

	store_err := store_data(&args, bufs.output)
	if store_err != nil {
		fmt.eprintln("Could not write file:", os.error_string(load_err))
		return
	}

	fmt.println("Results written to", args.output)
}

load_data :: proc(args: ^arguments.Arguments) -> (bufs: aes.Buffers, err: os.Error) {
	file := os.open(args.input) or_return
	defer os.close(file)

	file_size := int(os.file_size(file) or_return)
	buf_size := file_size
	if args.op == .Encrypt {
		buf_size += pkcs7_compute_padding(buf_size)
	}

	buf := make([]u8, buf_size * 2)
	os.read(file, buf) or_return

	padding := buf_size - file_size
	mem.set(raw_data(buf[file_size:]), u8(padding), padding)

	bufs.input = buf[:buf_size]
	bufs.output = buf[buf_size:]
	return
}

store_data :: proc(args: ^arguments.Arguments, data: []u8) -> (err: os.Error) {
	size := len(data)
	if args.op == .Decrypt {
		pad := pkcs7_read_padding(data)
		ensure(pad > 0 && pad < size, "Invalid padding value")
		size -= pad
	}

	os.write_entire_file(args.output, data[:size]) or_return
	return
}

pkcs7_compute_padding :: proc(size: int) -> int {
	PADDING :: aes.BLOCK_SIZE // NOTE: AES-128
	aligned := mem.align_formula(size, PADDING)
	return aligned == 0 ? PADDING : aligned - size
}

pkcs7_read_padding :: proc(buf: []u8) -> int {
	return int(buf[len(buf) - 1])
}
