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

import org.bridj.Pointer;

import hu.keve.capstonebinding.CapstoneLibrary.cs_arch;
import hu.keve.capstonebinding.CapstoneLibrary.cs_mode;
import hu.keve.capstonebinding.CapstoneLibrary.cs_opt_type;
import hu.keve.capstonebinding.CapstoneLibrary.cs_opt_value;
import hu.keve.capstonebinding.cs_detail;
import hu.keve.capstonebinding.cs_insn;
import hu.keve.capstonebinding.cs_x86;
import hu.keve.capstonebinding.cs_x86_op;
import hu.keve.capstonej.Capstone.RegsAccess;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class TestX86 extends TestCase {
    /**
     * Create the test case
     *
     * @param testName
     *            name of the test case
     */
    public TestX86(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(TestX86.class);
    }

    private static final String X86_CODE64 = "55488b05b81300008fe860cde207";

    public void testX86() throws CapstoneException {
        System.err.format("Binding %d.%d\n", Capstone.getBindingApiMajor(), Capstone.getBindingApiMinor());
        System.err.format("Library %d.%d\n", Capstone.getLibraryApiMajor(), Capstone.getLibraryApiMinor());
        System.err.format("Supports all archs %b\n", Capstone.isSupported(cs_arch.CS_ARCH_ALL));
        System.err.format("Supports PPC: %b\n", Capstone.isSupported(cs_arch.CS_ARCH_PPC));

        Capstone capstone = new Capstone(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_64);
        try {
            capstone.setOption(cs_opt_type.CS_OPT_DETAIL, cs_opt_value.CS_OPT_ON);
            capstone.setOption(cs_opt_type.CS_OPT_SYNTAX, cs_opt_value.CS_OPT_SYNTAX_INTEL);

            byte[] buf = Util.hexString2Byte(X86_CODE64);
            CapstoneDisassembly disasm = capstone.disasm(buf, 0x1000l);
            try {
                for (Pointer<cs_insn> isP : disasm) {
                    cs_insn is = isP.get();
                    System.out.println(is);
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
                    cs_x86 isdX86 = isd.field1().x86();
                    System.out.println(isdX86);
                    for (int opc = 0; opc < isdX86.op_count(); opc++) {
                        cs_x86_op op = isdX86.operands().get(opc);
                        System.out.println(op);
                    }

                    RegsAccess regsAccess = capstone.regsAccess(isP);
                    System.out.println("Registers read:");
                    for (short reg : regsAccess.regsRead) {
                        System.out.printf(" %s", capstone.regName(reg));
                    }
                    System.out.println();
                    System.out.println("Registers written:");
                    for (short reg : regsAccess.regsWritten) {
                        System.out.printf(" %s", capstone.regName(reg));
                    }
                    System.out.println();
                }
            } finally {
                disasm.close();
            }
        } finally {
            capstone.close();
        }
    }
}