package ch.securify;
import ch.securify.decompiler.EvmParser;
import ch.securify.decompiler.evm.OpCodes;
import ch.securify.decompiler.evm.RawInstruction;
import com.google.common.io.BaseEncoding;
import org.junit.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.System.*;
import static org.junit.Assert.*;

public class EvmParserTest {
    @Test
    public void testLinearJumpDestinations() {
        // Input byte code as start
        chkJumpDestinations("6080604052600436106043576000357c0100000000000000000000000000000000000000000000000000000000900480638a4068dd146048578063d0e30db0146050575b600080fd5b604e6058565b005b60566060565b005b600034905050565b56fea165627a7a72305820bedc84d9b083d78befe7ede32318c950ba14a0808c3c2b5ee4ba6e765095cf490029",
                Arrays.asList(67, 72, 78, 80, 86, 88, 96));
    }

    @Test
    public void testIfJumpDestination() {
        chkJumpDestinations("6080604052600436106043576000357c0100000000000000000000000000000000000000000000000000000000900480638a4068dd146048578063d0e30db0146050575b600080fd5b604e6058565b005b60566081565b005b60003490506001811415607e573373ffffffffffffffffffffffffffffffffffffffff16ff5b50565b56fea165627a7a72305820c0b84cbf0b05b229d0cf35efa118c671b5d661572b7be5e0ba684ec2e517266b0029",
                Arrays.asList(67, 72, 78, 80, 86, 88, 126, 129));
    }

    public void chkJumpDestinations(String byteString, List<Integer> expdDestinations) {
        // raw EVM instructions
        byte byteCode[] = BaseEncoding.base16().lowerCase().decode(byteString.toLowerCase());

        RawInstruction[] rawInstructions = new RawInstruction[byteCode.length + 1];
        List<Integer> jumpDestinations = new ArrayList<>();

        // Raw Instructions = parseRawInstructions() (probably need a test for that!!) Think of some really challenging instruction outcomes
        // especially with exotic jump destinations
        // parse raw instructions
        EvmParser.parse(byteCode, (offset, instrNumber, opcode, payload) -> {
            rawInstructions[offset] = new RawInstruction(opcode, payload, offset, instrNumber);
            out.println(rawInstructions[offset].toString());
            if (opcode == OpCodes.JUMPDEST) {
                jumpDestinations.add(offset);
            }
        });

        out.println(jumpDestinations);
        out.println(expdDestinations);

        assertArrayEquals(expdDestinations.toArray(), jumpDestinations.toArray());
    }
}
