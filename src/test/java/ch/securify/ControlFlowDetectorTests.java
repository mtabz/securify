package ch.securify;

import ch.securify.decompiler.ControlFlowDetector;
import ch.securify.decompiler.evm.OpCodes;
import ch.securify.decompiler.evm.RawInstruction;
import com.google.common.collect.Multimap;
import com.google.common.io.BaseEncoding;
import org.apache.commons.codec.binary.Hex;
import org.junit.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static java.lang.System.*;
import static org.junit.Assert.*;

public class ControlFlowDetectorTests {
    /**
     * Test cases:
     * 1. Long jumps should not cause any issues
     * 2. For loops should work
     * 3. Function calls should work
     * 4. If-Else statements should work
     * 5. Recursion should work
     */
    /**
     * TODO: Separate out RawInstruction population and branchSrcs verification into Before and After primitives
     */
    @Test
    public void testIfElse () {
        // What branches should be found at the end of this?
        List<Integer> correctBranchSrcs = Arrays.asList(0, 9, 16, 17, 22, 24);

        RawInstruction listInstructions[];
        try {   // Try to catch exceptions in decodeHex class
            // Create raw instructions
            // RawInstruction[] rawInstructions = {
            listInstructions = new RawInstruction[]{
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("00"), 0, 1),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("64"), 2, 2),
                    new RawInstruction(OpCodes.DUP(2), null, 4, 3),
                    new RawInstruction(OpCodes.LT, null, 5, 4),
                    new RawInstruction(OpCodes.ISZERO, null, 6, 5),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("11"), 7, 6),
                    new RawInstruction(OpCodes.JUMPI, null, 9, 7),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("FF"), 10, 8),
                    new RawInstruction(OpCodes.SWAP(1), null, 12, 9),
                    new RawInstruction(OpCodes.POP, null, 13, 10),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("17"), 14, 11),
                    new RawInstruction(OpCodes.JUMP, null, 16, 12),
                    new RawInstruction(OpCodes.JUMPDEST, null, 17, 13),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("40"), 18, 14),
                    new RawInstruction(OpCodes.SWAP(1), null, 20, 15),
                    new RawInstruction(OpCodes.POP, null, 21, 16),
                    new RawInstruction(OpCodes.JUMPDEST, null, 22, 17),
                    new RawInstruction(OpCodes.POP, null, 23, 18),
                    new RawInstruction(OpCodes.STOP, null, 24, 19),
                    new RawInstruction(OpCodes.INVALID, null, 2102, -1)};
        } catch (Exception e) {
            listInstructions = new RawInstruction[] {new RawInstruction(OpCodes.INVALID, null, 0, 1)};
            out.println(e);
            assert(false);
        }

        // Populate rawInstructions from the list of Instructions
        RawInstruction[] rawInstructions = new RawInstruction[listInstructions[listInstructions.length-1].offset+1];
        for (int i=0; i<listInstructions.length; i++) {
            rawInstructions[listInstructions[i].offset] = listInstructions[i];
        }

        ControlFlowDetector controlFlowDetector = new ControlFlowDetector();
        controlFlowDetector.computeBranches(rawInstructions, out);

        /* Then getBranches() and verify that the rxd branches are what is expected
         * Control flow graph: maps from jumps to possible jump destinations and
         * from jump destinations to the next jump instruction. */
        Multimap<Integer, Integer> controlFlowGraph = controlFlowDetector.getBranches();
        List<Integer> branchSrcs = new ArrayList<>(controlFlowGraph.asMap().keySet());
        Collections.sort(branchSrcs);

        assertEquals(correctBranchSrcs,branchSrcs);
    }

    @Test
    public void testForLoop () {
    }

    @Test
    public void testLongJump () {
        // What branches should be found at the end of this?
        List<Integer> correctBranchSrcs = Arrays.asList(0, 3, 2100, 2101);

        RawInstruction listInstructions[];
        try {   // Try to catch exceptions in decodeHex class
            // Create raw instructions
            // RawInstruction[] rawInstructions = {
            listInstructions = new RawInstruction[]{
                    new RawInstruction(OpCodes.PUSH(2), Hex.decodeHex("0834"), 0, 1),
                    new RawInstruction(OpCodes.JUMP, null, 3, 2),
                    new RawInstruction(OpCodes.JUMPDEST, null, 2100, 3),
                    new RawInstruction(OpCodes.STOP, null, 2101, 4),
                    new RawInstruction(OpCodes.INVALID, null, 2102, -1)};
        } catch (Exception e) {
            listInstructions = new RawInstruction[] {new RawInstruction(OpCodes.INVALID, null, 0, 1)};
            out.println(e);
            assert(false);
        }

        // Populate rawInstructions from the list of Instructions
        RawInstruction[] rawInstructions = new RawInstruction[listInstructions[listInstructions.length-1].offset+1];
        for (int i=0; i<listInstructions.length; i++) {
            rawInstructions[listInstructions[i].offset] = listInstructions[i];
        }

        ControlFlowDetector controlFlowDetector = new ControlFlowDetector();
        controlFlowDetector.computeBranches(rawInstructions, out);

        /* Then getBranches() and verify that the rxd branches are what is expected
         * Control flow graph: maps from jumps to possible jump destinations and
         * from jump destinations to the next jump instruction. */
        Multimap<Integer, Integer> controlFlowGraph = controlFlowDetector.getBranches();
        List<Integer> branchSrcs = new ArrayList<>(controlFlowGraph.asMap().keySet());
        Collections.sort(branchSrcs);

        assertEquals(correctBranchSrcs,branchSrcs);
    }

     /**
     * Control flow with mulitple jumps. The instructions in this correspond to LockedEther.sol (compiled
      * with solc v0.5.2)
     */
    @Test
    public void testLockedEtherControlFlow() {
        // What branches should be found at the end of this?
        List<Integer> correctBranchSrcs = Arrays.asList(0, 11, 56, 66, 67, 71, 72, 77, 78, 79, 80, 85, 86, 87, 88, 95, 96, 97);

        RawInstruction listInstructions[];
        try {   // Try to catch exceptions in decodeHex class
            // Create raw instructions
            // RawInstruction[] rawInstructions = {
            listInstructions = new RawInstruction[] {
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("80"), 0, 1),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("40"), 2, 2 ),
                    new RawInstruction(OpCodes.MSTORE, null, 4, 3),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("04"), 5, 4),
                    new RawInstruction(OpCodes.CALLDATASIZE, null, 7, 5),
                    new RawInstruction(OpCodes.LT, null, 8, 6),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("43"), 9, 7),
                    new RawInstruction(OpCodes.JUMPI, null, 11, 8),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("00"), 12, 9),
                    new RawInstruction(OpCodes.CALLDATALOAD, null, 14, 10),
                    new RawInstruction(OpCodes.PUSH(29), Hex.decodeHex("0100000000000000000000000000000000000000000000000000000000"), 15, 11),
                    new RawInstruction(OpCodes.SWAP(1), null, 45, 12),
                    new RawInstruction(OpCodes.DIV, null, 46, 13),
                    new RawInstruction(OpCodes.DUP(1), null, 47, 14),
                    new RawInstruction(OpCodes.PUSH(4), Hex.decodeHex("8A4068DD"), 48, 15),
                    new RawInstruction(OpCodes.EQ, null, 53, 16),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("48"), 54, 17),
                    new RawInstruction(OpCodes.JUMPI, null, 56, 18),
                    new RawInstruction(OpCodes.DUP(1), null, 57, 19),
                    new RawInstruction(OpCodes.PUSH(4), Hex.decodeHex("D0E30DB0"), 58, 20),
                    new RawInstruction(OpCodes.EQ, null, 63, 21),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("50"), 64, 22),
                    new RawInstruction(OpCodes.JUMPI, null, 66, 23),
                    new RawInstruction(OpCodes.JUMPDEST, null, 67, 24),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("00"), 68, 25),
                    new RawInstruction(OpCodes.DUP(1), null, 70, 26),
                    new RawInstruction(OpCodes.REVERT, null, 71, 27),
                    new RawInstruction(OpCodes.JUMPDEST, null, 72, 28),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("4E"), 73, 29),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("58"), 75, 30),
                    new RawInstruction(OpCodes.JUMP, null, 77, 31),
                    new RawInstruction(OpCodes.JUMPDEST, null, 78, 32),
                    new RawInstruction(OpCodes.STOP, null, 79, 33),
                    new RawInstruction(OpCodes.JUMPDEST, null, 80, 34),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("56"), 81, 35),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("60"), 83, 36),
                    new RawInstruction(OpCodes.JUMP, null, 85, 37),
                    new RawInstruction(OpCodes.JUMPDEST, null, 86, 38),
                    new RawInstruction(OpCodes.STOP, null, 87, 39),
                    new RawInstruction(OpCodes.JUMPDEST,null, 88,40),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("00"), 89, 41),
                    new RawInstruction(OpCodes.CALLVALUE, null, 91, 42),
                    new RawInstruction(OpCodes.SWAP(1), null, 92, 43),
                    new RawInstruction(OpCodes.POP, null, 93, 44),
                    new RawInstruction(OpCodes.POP, null, 94, 45),
                    new RawInstruction(OpCodes.JUMP, null, 95, 46),
                    new RawInstruction(OpCodes.JUMPDEST, null, 96, 47),
                    new RawInstruction(OpCodes.JUMP, null, 97, 48),
                    new RawInstruction(OpCodes.INVALID, null, 98, 49),
                    new RawInstruction(OpCodes.LOG1, null, 99, 50),
                    new RawInstruction(OpCodes.PUSH(6), Hex.decodeHex("627A7A723058"), 100, 51),
                    new RawInstruction(OpCodes.SHA3, null, 107, 52),
                    new RawInstruction(OpCodes.INVALID, null, 108, 53),
                    new RawInstruction(OpCodes.INVALID, null, 109, 54),
                    new RawInstruction(OpCodes.DUP(1), null, 110, 55),
                    new RawInstruction(OpCodes.INVALID, null, 111, 56),
                    new RawInstruction(OpCodes.INVALID, null, 112, 57),
                    new RawInstruction(OpCodes.DUP(1), null, 113, 58),
                    new RawInstruction(OpCodes.INVALID, null, 114, 59),
                    new RawInstruction(OpCodes.DUP(1), null, 115, 60),
                    new RawInstruction(OpCodes.INVALID, null, 116, 61),
                    new RawInstruction(OpCodes.INVALID, null, 117, 62),
                    new RawInstruction(OpCodes.INVALID, null, 118, 63),
                    new RawInstruction(OpCodes.INVALID, null, 119, 64),
                    new RawInstruction(OpCodes.INVALID, null, 120, 65),
                    new RawInstruction(OpCodes.XOR, null, 121, 66),
                    new RawInstruction(OpCodes.INVALID, null, 122, 67),
                    new RawInstruction(OpCodes.POP, null, 123, 68),
                    new RawInstruction(OpCodes.INVALID, null, 124, 69),
                    new RawInstruction(OpCodes.EQ, null, 125, 70),
                    new RawInstruction(OpCodes.LOG0, null, 126, 71),
                    new RawInstruction(OpCodes.DUP(1), null, 127, 72),
                    new RawInstruction(OpCodes.DUP(1), null, 128, 73),
                    new RawInstruction(OpCodes.EXTCODECOPY, null, 129, 74),
                    new RawInstruction(OpCodes.INVALID, null, 130, 75),
                    new RawInstruction(OpCodes.INVALID, null, 131, 76),
                    new RawInstruction(OpCodes.INVALID, null, 132, 77),
                    new RawInstruction(OpCodes.INVALID, null, 133, 78),
                    new RawInstruction(OpCodes.PUSH(15), Hex.decodeHex("765095CF4900290000000000000000"), 134, 79),
                    new RawInstruction(OpCodes.INVALID, null, 142, -1)};
        } catch (Exception e) {
            listInstructions = new RawInstruction[] {new RawInstruction(OpCodes.INVALID, null, 0, 1)};
            out.println(e);
            assert(false);
        }

        // Populate rawInstructions from the list of Instructions
        RawInstruction[] rawInstructions = new RawInstruction[listInstructions[listInstructions.length-1].offset+1];
        for (int i=0; i<listInstructions.length; i++) {
            rawInstructions[listInstructions[i].offset] = listInstructions[i];
        }

        ControlFlowDetector controlFlowDetector = new ControlFlowDetector();
        controlFlowDetector.computeBranches(rawInstructions, out);

        /* Then getBranches() and verify that the rxd branches are what is expected
         * Control flow graph: maps from jumps to possible jump destinations and
         * from jump destinations to the next jump instruction. */
        Multimap<Integer, Integer> controlFlowGraph = controlFlowDetector.getBranches();
        List<Integer> branchSrcs = new ArrayList<>(controlFlowGraph.asMap().keySet());
        Collections.sort(branchSrcs);

        assertEquals(correctBranchSrcs,branchSrcs);
    }

    /**
     * This test checks that there is an exception when there is a mismatch between the number of instructions
     * and offsets referenced.
     */
    @Test
    public void testOutOfBoundsException() {
        RawInstruction rawInstructions[];
        try {   // Try to catch exceptions in decodeHex class
            // Create raw instructions
            // RawInstruction[] rawInstructions = {
            rawInstructions = new RawInstruction[] {
                    new RawInstruction(OpCodes.PUSH(1), BaseEncoding.base16().lowerCase().decode("80".toLowerCase()), 0, 1),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("40"), 2, 2 ),
                    new RawInstruction(OpCodes.MSTORE, null, 4, 3),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("04"), 5, 4),
                    new RawInstruction(OpCodes.CALLDATASIZE, null, 7, 5),
                    new RawInstruction(OpCodes.LT, null, 8, 6),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("43"), 9, 7),
                    new RawInstruction(OpCodes.JUMPI, null, 11, 8),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("00"), 12, 9),
                    new RawInstruction(OpCodes.CALLDATALOAD, null, 14, 10),
                    new RawInstruction(OpCodes.PUSH(29), Hex.decodeHex("0100000000000000000000000000000000000000000000000000000000"), 15, 11),
                    new RawInstruction(OpCodes.SWAP(1), null, 45, 12),
                    new RawInstruction(OpCodes.DIV, null, 46, 13),
                    new RawInstruction(OpCodes.DUP(0), null, 47, 14),
                    new RawInstruction(OpCodes.PUSH(4), Hex.decodeHex("8A4068DD"), 48, 15),
                    new RawInstruction(OpCodes.EQ, null, 53, 16),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("48"), 54, 17),
                    new RawInstruction(OpCodes.JUMPI, null, 56, 18),
                    new RawInstruction(OpCodes.DUP(0), null, 57, 19),
                    new RawInstruction(OpCodes.PUSH(4), Hex.decodeHex("D0E30DB0"), 58, 20),
                    new RawInstruction(OpCodes.EQ, null, 63, 21),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("80"), 64, 22),
                    new RawInstruction(OpCodes.JUMPI, null, 66, 23),
                    new RawInstruction(OpCodes.JUMPDEST, null, 67, 24),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("00"), 68, 25),
                    new RawInstruction(OpCodes.DUP(0), null, 70, 26),
                    new RawInstruction(OpCodes.REVERT, null, 71, 27),
                    new RawInstruction(OpCodes.JUMPDEST, null, 72, 28),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("4E"), 73, 29),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("58"), 75, 30),
                    new RawInstruction(OpCodes.JUMP, null, 77, 31),
                    new RawInstruction(OpCodes.JUMPDEST, null, 78, 32),
                    new RawInstruction(OpCodes.STOP, null, 79, 33),
                    new RawInstruction(OpCodes.JUMPDEST, null, 80, 34),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("56"), 81, 35),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("60"), 83, 36),
                    new RawInstruction(OpCodes.JUMP, null, 85, 37),
                    new RawInstruction(OpCodes.JUMPDEST, null, 86, 38),
                    new RawInstruction(OpCodes.STOP, null, 87, 39),
                    new RawInstruction(OpCodes.JUMPDEST,null, 88,40),
                    new RawInstruction(OpCodes.PUSH(1), Hex.decodeHex("00"), 89, 41),
                    new RawInstruction(OpCodes.CALLVALUE, null, 91, 42),
                    new RawInstruction(OpCodes.SWAP(0), null, 92, 43),
                    new RawInstruction(OpCodes.POP, null, 93, 44),
                    new RawInstruction(OpCodes.POP, null, 94, 45),
                    new RawInstruction(OpCodes.JUMP, null, 95, 46),
                    new RawInstruction(OpCodes.JUMPDEST, null, 96, 47),
                    new RawInstruction(OpCodes.JUMP, null, 97, 48),
                    new RawInstruction(OpCodes.INVALID, null, 98, 49),
                    new RawInstruction(OpCodes.LOG1, null, 99, 50),
                    new RawInstruction(OpCodes.PUSH(6), Hex.decodeHex("627A7A723058"), 100, 51),
                    new RawInstruction(OpCodes.SHA3, null, 107, 52),
                    new RawInstruction(OpCodes.INVALID, null, 108, 53),
                    new RawInstruction(OpCodes.INVALID, null, 109, 54)};
        } catch (Exception e) {
            rawInstructions = new RawInstruction[] {new RawInstruction(OpCodes.INVALID, null, 0, 1)};
            out.println(e);
            assert(false);
        }

        try {
            // Use Raw Instructions to computeBranches()
            ControlFlowDetector controlFlowDetector = new ControlFlowDetector();
            controlFlowDetector.computeBranches(rawInstructions, null);
            assertTrue("Should have had an out of bounds exception", false);
        } catch (ArrayIndexOutOfBoundsException e) {
            assertTrue(true);
        }
    }
}
