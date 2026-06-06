package arguments

import "core:container/intrusive/list"
import "core:reflect"
import "core:strconv"
import "core:text/scanner"

Arguments :: struct {
	key:    Maybe(u128),
	iv:     Maybe(u128),
	input:  string,
	output: string,
	op:     Operation,
	mode:   Mode,
}

Mode :: enum {
	None,
	ECB,
	CBC,
}

Element :: struct {
	node: list.Node,
	value: string,
}

Operation :: enum {
	None,
	Encrypt,
	Decrypt,
}

Type :: enum {
	String,
	Mode,
	Vector,
	Operation,
}

parse :: proc(args: []string) -> (result: Arguments, err: string) {
	l := list_from_args(args)
	it := list.iterator_head(l, Element, "node")

    parse_arg(&result.input, &l, .String, "-i")
    parse_arg(&result.output, &l, .String, "-o")
    parse_arg(&result.mode, &l, .Mode, "-m")
    parse_arg(&result.iv, &l, .Vector, "-v")
    parse_arg(&result.key, &l, .Vector, "-k")

    // NOTE: leave op for last since it has no switch
    parse_arg(&result.op, &l, .Operation)

    return
}

parse_arg :: proc(
	dst: rawptr,
	l: ^list.List,
	type: Type,
	name := "",
) {
	it := list.iterator_head(l^, Element, "node")
	if list.is_empty(l) {
		return
	}

	val := ""
	if name == "" {
		elem := (^Element)(list.pop_front(l))
		val = elem.value
	} else {
		for elem in list.iterate_next(&it) {
			if elem.value == name {
				next, ok := list.iterate_next(&it)
				ensure(ok, "Missing value for switch")

				list.remove(l, &elem.node)
				list.remove(l, &next.node)

				val = next.value
				break
			}
		}
	}

	if val == "" {
		return // NOTE: nothing found
	}

	switch type {
	case .String:
		 (^string)(dst)^ = val
	case .Mode:
		 (^Mode)(dst)^ = mode_scan(val)
	case .Vector:
		 (^Maybe(u128))(dst)^ = vector_scan(val)
	case .Operation:
		 (^Operation)(dst)^ = operation_scan(val)
	}
}

state_is_valid :: proc(args: ^Arguments) -> bool {
	return args.input != "" &&
		args.output != "" &&
		args.op != .None &&
		args.mode != .None &&
		args.key != nil &&
		(args.mode != .CBC || args.iv != nil)
}

list_from_args :: proc(args: []string) -> (result: list.List) {
	elems := make([]Element, len(args))
	for arg, i in args {
		elems[i].value = arg
		list.push_back(&result, &elems[i].node)
	}

	return
}

mode_scan :: proc(name: string) -> Mode {
	mode, ok :=  reflect.enum_from_name(Mode, name)
	return ok ? mode : .None
}

operation_scan :: proc(name: string) -> Operation {
	switch name {
	case "encrypt":
		return .Encrypt
	case "decrypt":
		return .Decrypt
	case:
		return .None
	}
}

vector_scan :: proc(input: string) -> u128 {
	BYTES_TO_SCAN :: 16
	MAX_VAL :: uint(max(u8))

	sc: scanner.Scanner
	scanner.init(&sc, input)
	sc.flags = {.Scan_Ints}

	scanned := 0
	bytes := [BYTES_TO_SCAN]u8{}
	for tok: rune; tok != scanner.EOF; tok = scanner.scan(&sc) {
		switch tok {
		case scanner.Int:
			ensure(scanned < BYTES_TO_SCAN, "Trailing values in vector input")

			text := scanner.token_text(&sc)
			val, _ := strconv.parse_uint(text, 10)
			ensure(val <= MAX_VAL, "Vector byte out of range")

			bytes[scanned] = u8(val)
			scanned += 1
		case ',', 0:
			continue
		case:
			ensure(false, "Invalid token on vector input")
		}
	}

	ensure(scanned == BYTES_TO_SCAN, "Not enough values in vector input")
	return transmute(u128)bytes
}
