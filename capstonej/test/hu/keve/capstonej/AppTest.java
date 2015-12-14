/*
Copyright (c) 2015, Keve Müller
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of capstonej nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package hu.keve.capstonej;

import hu.keve.capstonebinding.CapstoneLibrary.cs_arch;
import hu.keve.capstonebinding.CapstoneLibrary.cs_mode;
import hu.keve.capstonebinding.CapstoneLibrary.cs_opt_type;
import hu.keve.capstonebinding.CapstoneLibrary.cs_opt_value;
import hu.keve.capstonebinding.CapstoneLibrary.ppc_bc;
import hu.keve.capstonebinding.CapstoneLibrary.ppc_bh;
import hu.keve.capstonebinding.CapstoneLibrary.ppc_op_type;
import hu.keve.capstonebinding.cs_detail;
import hu.keve.capstonebinding.cs_insn;
import hu.keve.capstonebinding.cs_ppc;
import hu.keve.capstonebinding.cs_ppc_op;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class AppTest extends TestCase {
    /**
     * Create the test case
     *
     * @param testName
     *            name of the test case
     */
    public AppTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(AppTest.class);
    }

    static byte[] hexString2Byte(String s) {
        // from
        // http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    static final String PPC_CODE = "80200000803f00001043230ed04400804c4322022d0300807c4320147c4320934f2000214cc8002140820014";

    public void testApp() throws CapstoneException {
        System.err.format("Binding %d.%d\n", Capstone.getBindingApiMajor(), Capstone.getBindingApiMinor());
        System.err.format("Library %d.%d\n", Capstone.getLibraryApiMajor(), Capstone.getLibraryApiMinor());
        System.err.format("Supports all archs %b\n", Capstone.isSupported(cs_arch.CS_ARCH_ALL));
        System.err.format("Supports PPC: %b\n", Capstone.isSupported(cs_arch.CS_ARCH_PPC));

        Capstone capstone = new Capstone(cs_arch.CS_ARCH_PPC, cs_mode.CS_MODE_32, cs_mode.CS_MODE_BIG_ENDIAN);
        try {
            capstone.setOption(cs_opt_type.CS_OPT_DETAIL, cs_opt_value.CS_OPT_ON);
            capstone.setOption(cs_opt_type.CS_OPT_SYNTAX, cs_opt_value.CS_OPT_SYNTAX_ATT);

            byte[] buf = hexString2Byte(PPC_CODE);
            CapstoneDisassembly disasm = capstone.disasm(buf, 0x1000l);
            try {
                for (cs_insn is : disasm) {
                    System.out.println(is);
                    // System.out.println(ppc_insn.fromValue(is.id()));
                    System.out.println("mnemonic: " + is.mnemonic().getCString());
                    System.out.println("op_str: " + is.op_str().getCString());
                    cs_detail isd = is.detail().get();
                    if (isd.regs_read_count() > 0) {
                        System.out.println(isd.regs_read());
                    }
                    if (isd.regs_write_count() > 0) {
                        System.out.println(isd.regs_write());
                    }
                    if (isd.groups_count() > 0) {
                        System.out.println(isd.groups());
                    }
                    cs_ppc ppcDetail = isd.field1().ppc();
                    if (ppcDetail.bc() != ppc_bc.PPC_BC_INVALID) {
                        System.out.println("bc: " + ppcDetail.bc());
                    }
                    if (ppcDetail.bh() != ppc_bh.PPC_BH_INVALID) {
                        System.out.println("bh: " + ppcDetail.bh());
                    }
                    System.out.println("update_cr0: " + ppcDetail.update_cr0());
                    for (int opc = 0; opc < ppcDetail.op_count(); opc++) {
                        cs_ppc_op op = ppcDetail.operands().get(opc);
                        if (op.type().value() == ppc_op_type.PPC_OP_REG.value()) {
                            System.out.format("op[%d]: REG = %s\n", opc, op.field1().reg());
                        } else if (op.type().value() == ppc_op_type.PPC_OP_IMM.value()) {
                            System.out.format("op[%d]: IMM = %s\n", opc, op.field1().imm());
                        } else if (op.type().value() == ppc_op_type.PPC_OP_MEM.value()) {
                            System.out.format("op[%d]: MEM = %s\n", opc, op.field1().mem());
                        } else if (op.type().value() == ppc_op_type.PPC_OP_CRX.value()) {
                            System.out.format("op[%d]: CRX = %s\n", opc, op.field1().crx());
                        } else {
                            System.err.format("op[%d]: UNKNOWN = %s\n", opc, op);
                        }
                    }
                }
            } finally {
                disasm.close();
            }
        } finally {
            capstone.close();
        }
    }
}
