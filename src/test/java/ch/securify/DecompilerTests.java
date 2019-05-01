package ch.securify;

import ch.securify.decompiler.instructions.Instruction;
import ch.securify.decompiler.instructions._VirtualMethodHead;
import ch.securify.decompiler.printer.DecompilationPrinter;
import ch.securify.utils.Hex;
import com.google.common.io.BaseEncoding;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import ch.securify.decompiler.*;

import static java.lang.System.out;
import static org.junit.Assert.*;

public class DecompilerTests {
    @Test
    public void testLinearJumpDecompile() {
        /**
         * Test code here is:
         * --
         * pragma solidity >=0.4.22 <0.6.0;
         *
         * contract MarketPlace {
         *     function transfer() public payable {
         *         uint x = msg.value;
         *     }
         * }
         *
         */
        // raw EVM instructions
        byte byteCode[] = BaseEncoding.base16().lowerCase().decode("6080604052600436106039576000357c0100000000000000000000000000000000000000000000000000000000900480638a4068dd14603e575b600080fd5b60446046565b005b60003490505056fea165627a7a723058202cf15776d1001545e44b00e1cdee8948b0315b56ff07600ab98429740ed1fe950029".toLowerCase());
        String[] correctInstructions = {"00:  \ta{}{?} = 0x80",
                "02:  \tb{}{?} = 0x40",
                "04:  \tmstore(memoffset: b{}{?}, value: a{}{?})",
                "05:  \tc{}{?} = 0x04",
                "07:  \td{}{?} = calldatasize()",
                "08:  \te{}{?} = (d{}{?} < c{}{?})",
                "0B:  \tif e{}{?}: goto tag_1 [merge @39]",
                "0C:  \th{}{?} = 0x00",
                "0E:  \ti{}{?} = calldataload(h{}{?})",
                "0F:  \tj{}{?} = 0x0100000000000000000000000000000000000000000000000000000000",
                "2E:  \tk{}{?} = i{}{?} / j{}{?}",
                "30:  \tl{}{?} = 0x8A4068DD",
                "35:  \tm{}{?} = (l{}{?} == k{}{?})",
                "38:  \tif m{}{?}: goto tag_2 [merge @3E]",
                "39:  \ttag_1: [from @0B]",
                "3A:  \tg{}{?} = 0x00",
                "3D:  \trevert(memoffset: g{}{?}, length: g{}{?})",
                "3E:  \ttag_2: [from @38]",
                "43:  \t() = method_abi_8A4068DD()",
                "45:  \tstop()",
                "46:  \tmethod_abi_8A4068DD()",
                "49:  \tr{}{?} = callvalue()",
                "4D:  \treturn ()"};

        List<Instruction> decompiledInstructions;

        decompiledInstructions = Decompiler.decompile(byteCode, out);

        DecompilationPrinter.printInstructions(decompiledInstructions, out);

        // Do we have the right number of instructions?
        assertEquals(correctInstructions.length, decompiledInstructions.size());

        // Verify instructions line by line
        AtomicInteger correctIndex = new AtomicInteger();
        decompiledInstructions.forEach(instruction -> {
            int corrIndex = correctIndex.getAndIncrement();
            assertEquals(correctInstructions[corrIndex], instruction.getDebugRepresentation());
		});
    }
}
