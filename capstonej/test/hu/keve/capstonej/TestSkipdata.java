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

import hu.keve.capstonebinding.CapstoneLibrary;
import hu.keve.capstonebinding.CapstoneLibrary.cs_arch;
import hu.keve.capstonebinding.CapstoneLibrary.cs_mode;
import hu.keve.capstonebinding.CapstoneLibrary.cs_opt_type;
import hu.keve.capstonebinding.CapstoneLibrary.cs_opt_value;
import hu.keve.capstonebinding.CapstoneLibrary.cs_skipdata_cb_t;
import hu.keve.capstonebinding.cs_insn;
import hu.keve.capstonebinding.cs_opt_skipdata;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class TestSkipdata extends TestCase {
    /**
     * Create the test case
     *
     * @param testName
     *            name of the test case
     */
    public TestSkipdata(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(TestSkipdata.class);
    }

    static final byte[] X86_CODE = Util.hexString2Byte("8d4c320801d881c634120000009192");
    static final String[] X86_CODE_DIS = { "00001000:\tlea ecx, [edx + esi + 8]", "00001004:\tadd eax, ebx",
            "00001006:\tadd esi, 0x1234", "0000100c:\t%s 0x00", "0000100d:\txchg eax, ecx",
            "0000100e:\txchg eax, edx" };

    static final byte[] ARM_CODE = Util
            .hexString2Byte("ed000000001a5a0f1fffc2098000000007f7eb2affff7f57e301ffff7f57eb00f0000024b24f0078");
    static final String[] ARM_CODE_DIS = { "00001000:\tandeq r0, r0, sp, ror #1", "00001004:\tsvceq #0x5a1a00",
            "00001008:\tstmibeq r2, {r0, r1, r2, r3, r4, r8, sb, sl, fp, ip, sp, lr, pc} ^",
            "0000100c:\tandeq r0, r0, r0, lsl #1", "00001010:\tbhs #0xffafec34",
            "00001014:\t.byte 0xff, 0xff, 0x7f, 0x57", "00001018:\t.byte 0xe3, 0x01, 0xff, 0xff",
            "0000101c:\trsceq r5, fp, pc, ror r7", "00001020:\tstrhs r0, [r0], #-0xf0",
            "00001024:\tstmdavc r0, {r1, r4, r5, r7, r8, sb, sl, fp, lr}" };

    public void assertEqualsDisasm(String[] lines, CapstoneDisassembly disasm, Object... args) {
        assertEquals(lines.length, disasm.getCount());
        int idx = 0;
        for (Pointer<cs_insn> isP : disasm) {
            cs_insn is = isP.get();
            String expectedLine = String.format(lines[idx], args);
            String line = String.format("%08x:\t%s %s", is.address(), is.mnemonic().getCString(),
                    is.op_str().getCString());
            System.out.println(line);
            assertEquals(expectedLine, line);
            idx++;
        }

    }

    public void testSkipDataX86() throws CapstoneException {
        Capstone capstone = new Capstone(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_32);
        try {
            capstone.setOption(cs_opt_type.CS_OPT_SKIPDATA, cs_opt_value.CS_OPT_ON);

            CapstoneDisassembly disasm = capstone.disasm(X86_CODE, 0x1000l);
            try {
                assertEqualsDisasm(X86_CODE_DIS, disasm, ".byte");
            } finally {
                disasm.close();
            }
        } finally {
            capstone.close();
        }
    }

    public void testSkipDataArm() throws CapstoneException {
        Capstone capstone = new Capstone(cs_arch.CS_ARCH_ARM, cs_mode.CS_MODE_ARM);
        try {
            capstone.setOption(cs_opt_type.CS_OPT_SKIPDATA, cs_opt_value.CS_OPT_ON);

            CapstoneDisassembly disasm = capstone.disasm(ARM_CODE, 0x1000l);
            try {
                assertEqualsDisasm(ARM_CODE_DIS, disasm, ".byte");
            } finally {
                disasm.close();
            }
        } finally {
            capstone.close();
        }
    }

    public void testSkipDataMnemonic() throws CapstoneException {
        Capstone capstone = new Capstone(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_32);
        try {
            capstone.setOption(cs_opt_type.CS_OPT_SKIPDATA, cs_opt_value.CS_OPT_ON);

            Pointer<cs_opt_skipdata> optionSkipDataP = Pointer.allocate(cs_opt_skipdata.class);
            cs_opt_skipdata optionSkipData = optionSkipDataP.get();
            optionSkipData.mnemonic(Pointer.pointerToCString(".db"));

            capstone.setOption(cs_opt_type.CS_OPT_SKIPDATA_SETUP, optionSkipDataP);

            CapstoneDisassembly disasm = capstone.disasm(X86_CODE, 0x1000l);
            try {
                assertEqualsDisasm(X86_CODE_DIS, disasm, ".db");
            } finally {
                disasm.close();
            }
        } finally {
            capstone.close();
        }
    }

    public void testSkipDataCallbackX86() throws CapstoneException {
        Capstone capstone = new Capstone(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_32);
        try {
            capstone.setOption(cs_opt_type.CS_OPT_SKIPDATA, cs_opt_value.CS_OPT_ON);

            Pointer<cs_opt_skipdata> optionSkipDataP = Pointer.allocate(cs_opt_skipdata.class);
            cs_opt_skipdata optionSkipData = optionSkipDataP.get();
            cs_skipdata_cb_t skipDataCallBack = new CapstoneLibrary.cs_skipdata_cb_t() {
                @Override
                public long apply(Pointer<Byte> code, long code_size, long offset, Pointer<?> user_data) {
                    // code is the buffer
                    // code_size is the size of the buffer
                    // offset is current offset
                    // user_data is anything we passed in user_data
                    // return - number of bytes to skip
                    System.err.format("skipping @ %08x %s\n", offset, user_data.getCString());
                    return 0; // anything but 0 will break things
                }
            };
            optionSkipData.user_data(Pointer.pointerToCString("# dummy user data"));
            optionSkipData.callback(skipDataCallBack.toPointer());

            capstone.setOption(cs_opt_type.CS_OPT_SKIPDATA_SETUP, optionSkipDataP);

            CapstoneDisassembly disasm = capstone.disasm(X86_CODE, 0x1000l);
            try {
                assertEqualsDisasm(X86_CODE_DIS, disasm, ".db");
            } finally {
                disasm.close();
            }
        } finally {
            capstone.close();
        }
    }

    public void testSkipDataCallbackArm() throws CapstoneException {
        Capstone capstone = new Capstone(cs_arch.CS_ARCH_ARM, cs_mode.CS_MODE_ARM);
        try {
            capstone.setOption(cs_opt_type.CS_OPT_SKIPDATA, cs_opt_value.CS_OPT_ON);

            Pointer<cs_opt_skipdata> optionSkipDataP = Pointer.allocate(cs_opt_skipdata.class);
            cs_opt_skipdata optionSkipData = optionSkipDataP.get();
            cs_skipdata_cb_t skipDataCallBack = new CapstoneLibrary.cs_skipdata_cb_t() {
                @Override
                public long apply(Pointer<Byte> code, long code_size, long offset, Pointer<?> user_data) {
                    // code is the buffer
                    // code_size is the size of the buffer
                    // offset is current offset
                    // user_data is anything we passed in user_data
                    // return - number of bytes to skip
                    System.err.format("ARM skipping @ %08x %s\n", offset, user_data.getCString());
                    return 0; // anything but 0 will break things
                }
            };
            optionSkipData.user_data(Pointer.pointerToCString("# dummy user data"));
            optionSkipData.callback(skipDataCallBack.toPointer());

            capstone.setOption(cs_opt_type.CS_OPT_SKIPDATA_SETUP, optionSkipDataP);

            CapstoneDisassembly disasm = capstone.disasm(ARM_CODE, 0x1000l);
            try {
                assertEqualsDisasm(ARM_CODE_DIS, disasm, ".db");
            } finally {
                disasm.close();
            }
        } finally {
            capstone.close();
        }
    }

}