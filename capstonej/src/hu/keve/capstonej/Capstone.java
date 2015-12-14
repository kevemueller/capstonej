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

import org.bridj.IntValuedEnum;
import org.bridj.Pointer;
import org.bridj.SizeT;

import hu.keve.capstonebinding.CapstoneLibrary;
import hu.keve.capstonebinding.CapstoneLibrary.cs_arch;
import hu.keve.capstonebinding.CapstoneLibrary.cs_err;
import hu.keve.capstonebinding.CapstoneLibrary.cs_mode;
import hu.keve.capstonebinding.CapstoneLibrary.cs_opt_type;
import hu.keve.capstonebinding.CapstoneLibrary.cs_opt_value;
import hu.keve.capstonebinding.cs_insn;
import hu.keve.capstonebinding.cs_opt_skipdata;

public final class Capstone {
    private Pointer<SizeT> handleP = Pointer.allocateSizeT();

    /**
     * Get the API major version number at binding generation time.
     * 
     * @return the API major version number from the header at binding
     *         generation time.
     */
    public static int getBindingApiMajor() {
        return CapstoneLibrary.CS_API_MAJOR;
    }

    /**
     * Get the API minor version number at binding generation time.
     * 
     * @return the API minor version number from the header at binding
     *         generation time.
     */
    public static int getBindingApiMinor() {
        return CapstoneLibrary.CS_API_MINOR;
    }

    /**
     * Get the API major version number at library compile time.
     * 
     * @return the API major version number from the header at library compile
     *         time.
     */
    public static int getLibraryApiMajor() {
        Pointer<Integer> major = Pointer.allocateInt();
        Pointer<Integer> minor = Pointer.allocateInt();
        CapstoneLibrary.csVersion(major, minor);
        return major.get().intValue();
    }

    /**
     * Get the API minor version number at library compile time.
     * 
     * @return the API minor version number from the header at library compile
     *         time.
     */
    public static int getLibraryApiMinor() {
        Pointer<Integer> major = Pointer.allocateInt();
        Pointer<Integer> minor = Pointer.allocateInt();
        CapstoneLibrary.csVersion(major, minor);
        return minor.get().intValue();
    }

    /**
     * Get API architecture support from library.
     * 
     * @param arch
     *            the architecture or cs_arch.CS_ARCH_ALL
     * @return true if the library supports this architecture
     */
    public static boolean isSupported(cs_arch arch) {
        return CapstoneLibrary.csSupport((int) arch.value());
    }

    /**
     * Instantiate Capstone for given architecture and modes.
     * 
     * @param arch
     *            the architecture
     * @param modes
     *            the modes
     */
    public Capstone(cs_arch arch, cs_mode... modes) throws CapstoneException {
        int modesI = 0;
        for (cs_mode mode : modes) {
            modesI |= mode.value();
        }
        IntValuedEnum<cs_err> err = CapstoneLibrary.csOpen(arch, cs_mode.fromValue(modesI), handleP);
        checkError(err);
    }

    public void setOption(cs_opt_type csOpt, cs_opt_value csOptValue) throws CapstoneException {
        IntValuedEnum<cs_err> err = CapstoneLibrary.csOption(handleP.getCLong(), csOpt, csOptValue.value());
        checkError(err);
    }

    public void setOption(cs_opt_type csOpt, Pointer<cs_opt_skipdata> skipDataOption) throws CapstoneException {
        IntValuedEnum<cs_err> err = CapstoneLibrary.csOption(handleP.getCLong(), csOpt, skipDataOption.getPeer());
        checkError(err);
    }

    public CapstoneDisassembly disasm(byte[] buf, long address) throws CapstoneException {
        Pointer<Pointer<cs_insn>> insn = Pointer.allocatePointer(cs_insn.class);
        Pointer<Byte> bufP = Pointer.pointerToBytes(buf);
        long count = CapstoneLibrary.csDisasm(handleP.getCLong(), bufP, buf.length, address, 0, insn);
        if (0 == count) {
            throw checkErrno();
        } else {
            return new CapstoneDisassembly(insn.get(), (int) count);
        }
    }

    public boolean isInsnInGroup(Pointer<cs_insn> insn, int group_id) {
        return CapstoneLibrary.csInsnGroup(handleP.getCLong(), insn, group_id);
    }

    public String groupName(int grp_id) {
        Pointer<Byte> grpNameBytes = CapstoneLibrary.csGroupName(handleP.getCLong(), grp_id);
        return null == grpNameBytes ? null : grpNameBytes.getCString();
    }

    public String regName(int reg_id) {
        Pointer<Byte> regNameBytes = CapstoneLibrary.csRegName(handleP.getCLong(), reg_id);
        return null == regNameBytes ? null : regNameBytes.getCString();
    }

    public static final class RegsAccess {
        short[] regsRead;
        short[] regsWritten;
    }

    public RegsAccess regsAccess(Pointer<cs_insn> insn) throws CapstoneException {
        Pointer<Short> regs_read = Pointer.allocateShorts(64);
        Pointer<Short> regs_write = Pointer.allocateShorts(64);
        Pointer<Byte> regs_read_count = Pointer.allocateByte();
        Pointer<Byte> regs_write_count = Pointer.allocateByte();
        IntValuedEnum<cs_err> err = CapstoneLibrary.csRegsAccess(handleP.getCLong(), insn, regs_read, regs_read_count,
                regs_write, regs_write_count);
        checkError(err);
        RegsAccess regsAccess = new RegsAccess();
        regsAccess.regsRead = regs_read.getShorts(regs_read_count.get());
        regsAccess.regsWritten = regs_write.getShorts(regs_write_count.get());
        return regsAccess;
    }

    // TODO: implement csDisasmIter

    public void close() throws CapstoneException {
        IntValuedEnum<cs_err> err = CapstoneLibrary.csClose(handleP);
        checkError(err);
    }

    private void checkError(IntValuedEnum<cs_err> err) throws CapstoneException {
        if (err == cs_err.CS_ERR_OK) {
            return;
        }
        throw new CapstoneException(err);
    }

    private CapstoneException checkErrno() {
        IntValuedEnum<cs_err> err = CapstoneLibrary.csErrno(handleP.getCLong());
        return new CapstoneException(err);
    }
}
