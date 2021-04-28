using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Linq;

namespace WpfStaticDLLInjection
{

    #region HeaderStruct
    public struct IMAGE_DOS_HEADER
    {      // DOS .EXE header
        public UInt16 e_magic;              // Magic number
        public UInt16 e_cblp;               // Bytes on last page of file
        public UInt16 e_cp;                 // Pages in file
        public UInt16 e_crlc;               // Relocations
        public UInt16 e_cparhdr;            // Size of header in paragraphs
        public UInt16 e_minalloc;           // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
        public UInt16 e_ss;                 // Initial (relative) SS value
        public UInt16 e_sp;                 // Initial SP value
        public UInt16 e_csum;               // Checksum
        public UInt16 e_ip;                 // Initial IP value
        public UInt16 e_cs;                 // Initial (relative) CS value
        public UInt16 e_lfarlc;             // File address of relocation table
        public UInt16 e_ovno;               // Overlay number
        public UInt16 e_res_0;              // Reserved words
        public UInt16 e_res_1;              // Reserved words
        public UInt16 e_res_2;              // Reserved words
        public UInt16 e_res_3;              // Reserved words
        public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;            // OEM information; e_oemid specific
        public UInt16 e_res2_0;             // Reserved words
        public UInt16 e_res2_1;             // Reserved words
        public UInt16 e_res2_2;             // Reserved words
        public UInt16 e_res2_3;             // Reserved words
        public UInt16 e_res2_4;             // Reserved words
        public UInt16 e_res2_5;             // Reserved words
        public UInt16 e_res2_6;             // Reserved words
        public UInt16 e_res2_7;             // Reserved words
        public UInt16 e_res2_8;             // Reserved words
        public UInt16 e_res2_9;             // Reserved words
        public UInt32 e_lfanew;             // File address of new exe header
    }

    public struct IMAGE_NT_HEADERS32
    {
        public UInt32 Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }
    public struct IMAGE_NT_HEADERS64
    {
        public UInt32 Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt32 BaseOfData;
        public UInt32 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt32 SizeOfStackReserve;
        public UInt32 SizeOfStackCommit;
        public UInt32 SizeOfHeapReserve;
        public UInt32 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;
    }
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;
    }
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    public struct IMAGE_SECTION_HEADER
    {
        public UInt64 Name;
        public UInt32 VirtualSize;
        public UInt32 VirtualAddress;
        public UInt32 SizeOfRawData;
        public UInt32 PointerToRawData;
        public UInt32 PointerToRelocations;
        public UInt32 PointerToLinenumbers;
        public UInt16 NumberOfRelocations;
        public UInt16 NumberOfLinenumbers;
        public UInt32 Characteristics;
    }
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        public UInt32 OriginalFirstThunk;
        public UInt32 TimeDateStamp;
        public UInt32 ForwarderChain;
        public UInt32 Name;
        public UInt32 FirstThunk;
    }

    #endregion
    class PEStructLoader
    {
        private bool _OpenFile = false;
        public IMAGE_DOS_HEADER _DOS_HEADER;
        private IMAGE_NT_HEADERS32 _NT_HEADERS32;
        private IMAGE_NT_HEADERS64 _NT_HEADERS64;
        private IMAGE_FILE_HEADER _FILE_HEADER;
        private System.IO.FileStream File;
        private IMAGE_DATA_DIRECTORY _IMPORT_DIRECTORY;
        private List<IMAGE_SECTION_HEADER> _SECTION_TABLE = new List<IMAGE_SECTION_HEADER>();
        private List<IMAGE_IMPORT_DESCRIPTOR> _IMPORT_TABLE = new List<IMAGE_IMPORT_DESCRIPTOR>();
        private bool _b32;
        private int _HeaderLength;
        private string Name;
        public PEStructLoader(string FileName)
        {
            _OpenFile = false;
            Name = FileName;
            File = new FileStream(FileName, System.IO.FileMode.Open);


            if (File != null)
            {
                LoadFile();

            }
            else
            {
                MessageBox.Show("Error Loading the file");
            }

            // File.Close();
            //File = new FileStream(FileName, System.IO.FileMode.Open);
            _OpenFile = true;
            File.Close();
        }
        #region ReadingHeaderFunctions
        private void LoadFile()
        {
            LoadDosHeader();//取DOS
            LoadNTHeader();
            LoadFileHeader();
            LoadSectionTable();  //获取节表
            LoadImportDirectory();
            LoadImportTable();
        }
        private void LoadDosHeader()
        {
            byte[] arr = new byte[64];
            File.Seek(0, 0);
            File.Read(arr, 0, 64);
            ByteToType<IMAGE_DOS_HEADER>(ref _DOS_HEADER, arr);
        }
        private void LoadFileHeader()
        {

            int index = Convert.ToInt32((_DOS_HEADER.e_lfanew + (uint)4));
            byte[] arr = new byte[20];
            File.Seek(index, 0);
            File.Read(arr, 0, 20);
            ByteToType<IMAGE_FILE_HEADER>(ref _FILE_HEADER, arr);
        }
        private void LoadNTHeader()
        {
            byte[] arr;
            int index = Convert.ToInt32(_DOS_HEADER.e_lfanew);
            int size;
            LoadFileHeader();

            if (_FILE_HEADER.Machine == 0x014c)
            {
                _b32 = true;
                size = 120;
            }
            else
            {
                _b32 = false;
                size = 136;
            }
            arr = new byte[size];
            File.Seek(index, 0);
            File.Read(arr, 0, size);
            if (_b32 == true)
            {
                ByteToType<IMAGE_NT_HEADERS32>(ref _NT_HEADERS32, arr);
            }
            else
            {
                ByteToType<IMAGE_NT_HEADERS64>(ref _NT_HEADERS64, arr);
            }

        }

        private void LoadImportDirectory()
        {
            int index;
            if (_b32 == true)
            {
                index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 128;
            }
            else
            {
                index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 144;
            }
            File.Seek(index, 0);
            byte[] arr = new byte[8];
            File.Read(arr, 0, 8);
            ByteToType<IMAGE_DATA_DIRECTORY>(ref _IMPORT_DIRECTORY, arr);

        }
        private void LoadImportTable()
        {
            UInt32 RAW = RVAToRAW(_IMPORT_DIRECTORY.VirtualAddress);
            int index = Convert.ToInt32(RAW);
            byte[] arr = new byte[20];
            File.Seek(index, 0);

            int count = Convert.ToInt32(_IMPORT_DIRECTORY.Size) / 20;
            for (int i = 0; i < count; i++)
            {

                IMAGE_IMPORT_DESCRIPTOR tmp = new IMAGE_IMPORT_DESCRIPTOR();
                File.Read(arr, 0, 20);
                
                ByteToType<IMAGE_IMPORT_DESCRIPTOR>(ref tmp, arr);
                if (tmp.FirstThunk == 0 && tmp.OriginalFirstThunk == 0)
                {
                    break;
                }
                _IMPORT_TABLE.Add(tmp);
            }

        }
        private void LoadSectionTable()
        {
            int index;
            int numOfDirectories;
            int numOfSections;
            byte[] arr = new byte[40];
            if (_b32 == true)
            {

                numOfDirectories = Convert.ToInt32(_NT_HEADERS32.OptionalHeader.NumberOfRvaAndSizes);
                index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 120 + numOfDirectories * 8;
                numOfSections = _NT_HEADERS32.FileHeader.NumberOfSections;
            }
            else
            {

                numOfDirectories = Convert.ToInt32(_NT_HEADERS64.OptionalHeader.NumberOfRvaAndSizes);
                index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 136 + numOfDirectories * 8;
                numOfSections = _NT_HEADERS64.FileHeader.NumberOfSections;
            }


            _HeaderLength = index;

            File.Seek(index, 0);
            IMAGE_SECTION_HEADER tmp = new IMAGE_SECTION_HEADER();
            for (int i = 0; i < numOfSections; i++)
            {
                File.Read(arr, 0, 40);
                
                ByteToType<IMAGE_SECTION_HEADER>(ref tmp, arr);
                _SECTION_TABLE.Add(tmp);
            }
        }
        #endregion ReadingHeaderFunctions
        #region ToolFunctions
        private void ByteToType<T>(ref T des, byte[] src)
        {
            GCHandle handle = GCHandle.Alloc(src, GCHandleType.Pinned);
            des = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
        }

        private byte[] TypeToByte<T>(ref T src)
        {
            int size = Marshal.SizeOf(src);
            byte[] arr = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(src, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        private UInt32 RVAToRAW(UInt32 RVA)
        {
            UInt32 RAW = RVA;
            int secNum = 0;
            if (RVA < _HeaderLength)
            {
                return RAW;
            }
            else
            {
                for (int i = _SECTION_TABLE.Count()-1; i >=0 ; i--)
                {
                    if (RVA > _SECTION_TABLE[i].VirtualAddress)
                    {
                        secNum = i;
                        break;
                    }
                }
            }

            RAW = RVA - _SECTION_TABLE[secNum].VirtualAddress + _SECTION_TABLE[secNum].PointerToRawData;
            return RAW;
        }

        private UInt32 RAWToRVA(UInt32 RAW)
        {
            UInt32 RVA = RAW;
            int secNum = 0;
            if (RAW < _HeaderLength)
            {
                return RVA;
            }
            else
            {
                for (int i = _SECTION_TABLE.Count() - 1; i >= 0; i--)
                {
                    if (RAW > _SECTION_TABLE[i].PointerToRawData)
                    {
                        secNum = i;
                        break;
                    }
                }
            }

            RVA = RAW - _SECTION_TABLE[secNum].PointerToRawData + _SECTION_TABLE[secNum].VirtualAddress;
            return RVA;
        }

        public void AddNewSection(string SectionName, UInt32 SectionSize)
        {
            File = new FileStream(this.Name, System.IO.FileMode.Open);
            UInt32 SecHeadindex;
            UInt32 NumberOfRvaAndSizes;
            UInt32 NumberOfSections;


            UInt32 FileAlignment, SectionAlignment, AlignedSecSize;
            if (_b32)
            {

                FileAlignment = _NT_HEADERS32.OptionalHeader.FileAlignment;
                SectionAlignment = _NT_HEADERS32.OptionalHeader.SectionAlignment;
                NumberOfRvaAndSizes = _NT_HEADERS32.OptionalHeader.NumberOfRvaAndSizes;
                NumberOfSections = _NT_HEADERS32.FileHeader.NumberOfSections;
            }
            else
            {

                FileAlignment = _NT_HEADERS64.OptionalHeader.FileAlignment;
                SectionAlignment = _NT_HEADERS64.OptionalHeader.SectionAlignment;
                NumberOfRvaAndSizes = _NT_HEADERS64.OptionalHeader.NumberOfRvaAndSizes;
                NumberOfSections = _NT_HEADERS64.FileHeader.NumberOfSections;
            }

            UInt32 SectionVA = _SECTION_TABLE.Last().VirtualAddress + GetAlignedSize(_SECTION_TABLE.Last().VirtualSize, SectionAlignment);
            UInt32 SectionRawOffset = _SECTION_TABLE.Last().PointerToRawData + GetAlignedSize(_SECTION_TABLE.Last().SizeOfRawData, FileAlignment);

            AlignedSecSize = GetAlignedSize(SectionSize, FileAlignment);
            SecHeadindex = _DOS_HEADER.e_lfanew + Convert.ToUInt32(Marshal.SizeOf<IMAGE_NT_HEADERS32>() +
                        NumberOfRvaAndSizes * Marshal.SizeOf<IMAGE_DATA_DIRECTORY>() + NumberOfSections * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
            File.Seek(_DOS_HEADER.e_lfanew, 0);
            if (_b32)
            {                
                _NT_HEADERS32.FileHeader.NumberOfSections += 1;
                _NT_HEADERS32.OptionalHeader.SizeOfImage += AlignedSecSize;
                WriteType<IMAGE_NT_HEADERS32>(ref _NT_HEADERS32);
            }
            else
            {
                _NT_HEADERS64.FileHeader.NumberOfSections += 1;
                _NT_HEADERS64.OptionalHeader.SizeOfImage += AlignedSecSize;
                WriteType<IMAGE_NT_HEADERS64>(ref _NT_HEADERS64);
            }

            
            IMAGE_SECTION_HEADER newSecHeader = new IMAGE_SECTION_HEADER();
            byte[] tmp = Encoding.ASCII.GetBytes(SectionName);
            UInt64 _Name = 0;
            ByteToType<UInt64>(ref _Name, tmp);

            newSecHeader.Name = _Name;
            newSecHeader.VirtualSize = AlignedSecSize;
            newSecHeader.VirtualAddress = SectionVA;
            newSecHeader.PointerToRawData = SectionRawOffset;
            newSecHeader.SizeOfRawData = AlignedSecSize;
            newSecHeader.Characteristics = 0x00000040 | 0x40000000 | 0x80000000 | 0x20000000;

            _SECTION_TABLE.Add(newSecHeader);
            File.Seek(SecHeadindex, 0);
            WriteType<IMAGE_SECTION_HEADER>(ref newSecHeader);

            byte[] filling = new byte[AlignedSecSize];
            File.Seek(SectionRawOffset, 0);
            File.Write(filling);
            File.Close();
        }
        public void StaticDLLInjectionByExtendingSection(string DllName, string FuncName)
        {
            File = new FileStream(this.Name, System.IO.FileMode.Open);
            UInt32 RAW = Convert.ToUInt32(File.Length);
            long OriginalLength = File.Length;
             
            int index;
            int numOfDirectories;
            double size = Math.Max(_SECTION_TABLE.Last().SizeOfRawData, _SECTION_TABLE[_SECTION_TABLE.Count - 1].VirtualSize);
            UInt32 SectionAlignment;
            UInt32 VirtualSize = _SECTION_TABLE.Last().VirtualSize;
            UInt32 SizeOfRawData = _SECTION_TABLE.Last().SizeOfRawData;
            UInt32 FileAllignment;

            IMAGE_SECTION_HEADER _tmp_sec_header;
            
            UInt32 fillingSize;
            if (_b32 == true)
            {
                numOfDirectories = Convert.ToInt32(_NT_HEADERS32.OptionalHeader.NumberOfRvaAndSizes);
                index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 120 + numOfDirectories * 8;
                SectionAlignment = _NT_HEADERS32.OptionalHeader.SectionAlignment;
                FileAllignment = _NT_HEADERS32.OptionalHeader.FileAlignment;
                _NT_HEADERS32.OptionalHeader.SizeOfImage += FileAllignment;

            }
            else
            {
                numOfDirectories = Convert.ToInt32(_NT_HEADERS64.OptionalHeader.NumberOfRvaAndSizes);
                index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 136 + numOfDirectories * 8;
                SectionAlignment = _NT_HEADERS64.OptionalHeader.SectionAlignment;
                FileAllignment = _NT_HEADERS64.OptionalHeader.FileAlignment;
                _NT_HEADERS64.OptionalHeader.SizeOfImage += FileAllignment;
            }

            _tmp_sec_header = _SECTION_TABLE.Last();
            if (size % 0x1000 != 0)
            {
                _tmp_sec_header.VirtualSize = (Convert.ToUInt32(size) / SectionAlignment + 1) * SectionAlignment + FileAllignment;
                _tmp_sec_header.SizeOfRawData = (Convert.ToUInt32(size) /  FileAllignment + 1) * FileAllignment + FileAllignment;

            }
            else
            {
                _tmp_sec_header.VirtualSize = Convert.ToUInt32(size) / SectionAlignment * SectionAlignment + FileAllignment;
                _tmp_sec_header.SizeOfRawData = Convert.ToUInt32(size) / FileAllignment * FileAllignment + FileAllignment;


            }
            fillingSize = _SECTION_TABLE.Last().SizeOfRawData - SizeOfRawData;

            if (_SECTION_TABLE.Last().Characteristics < 0x80000000)
            {
                _tmp_sec_header.Characteristics += 0x80000000;
            }

            _SECTION_TABLE[_SECTION_TABLE.Count -1] = _tmp_sec_header;
            

            index = index + (40 * (_SECTION_TABLE.Count() - 1));


            File.Seek(index, 0);
            _tmp_sec_header = _SECTION_TABLE.Last();
            WriteType<IMAGE_SECTION_HEADER>(ref _tmp_sec_header);
            byte[] filling = new byte[fillingSize];
            File.Seek(File.Length, 0);
            File.Write(filling);

            index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 4 + 20;
            File.Seek(index, 0);
            if(_b32)
            {
                WriteType<IMAGE_OPTIONAL_HEADER32>(ref _NT_HEADERS32.OptionalHeader);
            }
            else
            {
                WriteType<IMAGE_OPTIONAL_HEADER64>(ref _NT_HEADERS64.OptionalHeader);
            }


            UInt32 offsetOfOriginalFirstThunk = RAW;
            UInt32 offsetOfFirstThunk = RAW + 8;
            UInt32 offsetOfDLLName = offsetOfFirstThunk + 8;
            UInt32 offsetOfIMAGE_IMPORT_BY_NAME = offsetOfDLLName + Convert.ToUInt32(DllName.Length) + 2;
            UInt32 offsetOfNew_IID = offsetOfIMAGE_IMPORT_BY_NAME + Convert.ToUInt32(FuncName.Length) + 6;


            UInt32 OriginalFirstThunk = offsetOfIMAGE_IMPORT_BY_NAME;
            UInt32 FirstThunk = OriginalFirstThunk;



            UInt32 RVAOfOffsetOriginalFirstThunk = RAWToRVA(offsetOfOriginalFirstThunk);
            UInt32 RVOffsetOfFirstThunk = RAWToRVA(offsetOfFirstThunk);
            UInt32 RVAOffsetOfDllName = RAWToRVA(offsetOfDLLName);

            UInt32 RVAOfOrignalFirstThunk = RAWToRVA(OriginalFirstThunk);
            UInt32 RVAOfFirstThunk = RAWToRVA(OriginalFirstThunk);
            UInt32 RVAOfOffsetOfNew_IID = RAWToRVA(offsetOfNew_IID);

            _IMPORT_DIRECTORY.Size += 0x14;
            _IMPORT_DIRECTORY.VirtualAddress = RVAOfOffsetOfNew_IID;


            if (_b32 == true)
            {
                index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 128;
            }
            else
            {
                index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 144;
            }

            File.Seek(index, 0);
            WriteType<IMAGE_DATA_DIRECTORY>(ref _IMPORT_DIRECTORY);

            File.Seek(offsetOfOriginalFirstThunk, 0);
            WriteType<UInt32>(ref RVAOfOrignalFirstThunk);
            File.Seek(offsetOfFirstThunk, 0);
            WriteType<UInt32>(ref RVAOfFirstThunk);
            File.Seek(offsetOfDLLName, 0);
            byte[] bytes = Encoding.ASCII.GetBytes(DllName);
            File.Write(bytes);
            File.Seek(offsetOfIMAGE_IMPORT_BY_NAME + 2, 0);
            bytes = Encoding.ASCII.GetBytes(FuncName);
            File.Write(bytes);
            IMAGE_IMPORT_DESCRIPTOR IID;
            File.Seek(offsetOfNew_IID, 0);
            IID.OriginalFirstThunk = RVAOfOffsetOriginalFirstThunk;
            IID.FirstThunk = RVOffsetOfFirstThunk;
            IID.Name = RVAOffsetOfDllName;
            IID.ForwarderChain = 0;
            IID.TimeDateStamp = 0;
            _IMPORT_TABLE.Add(IID);
            IMAGE_IMPORT_DESCRIPTOR tmp;
            for (int i = 0; i < _IMPORT_TABLE.Count; i++)
            {
                tmp = _IMPORT_TABLE[i];
                WriteType<IMAGE_IMPORT_DESCRIPTOR>(ref tmp);
            }
            File.Close();
        }
        public void StaticDLLInjectionByAddingSection(string DllName, string FuncName)
        {

            AddNewSection(".Patch", 1024);

            IMAGE_SECTION_HEADER LastSecHeader = _SECTION_TABLE.Last();
            File = new FileStream(this.Name, System.IO.FileMode.Open);
            UInt32 RAW = LastSecHeader.PointerToRawData;

            int index;
           

            UInt32 offsetOfOriginalFirstThunk = RAW;
            UInt32 offsetOfFirstThunk = RAW + 8;
            UInt32 offsetOfDLLName = offsetOfFirstThunk + 8;
            UInt32 offsetOfIMAGE_IMPORT_BY_NAME = offsetOfDLLName + Convert.ToUInt32(DllName.Length) + 2;
            UInt32 offsetOfNew_IID = offsetOfIMAGE_IMPORT_BY_NAME + Convert.ToUInt32(FuncName.Length) + 6;


            UInt32 OriginalFirstThunk = offsetOfIMAGE_IMPORT_BY_NAME;
            UInt32 FirstThunk = OriginalFirstThunk;



            UInt32 RVAOfOffsetOriginalFirstThunk = RAWToRVA(offsetOfOriginalFirstThunk);
            UInt32 RVOffsetOfFirstThunk = RAWToRVA(offsetOfFirstThunk);
            UInt32 RVAOffsetOfDllName = RAWToRVA(offsetOfDLLName);

            UInt32 RVAOfOrignalFirstThunk = RAWToRVA(OriginalFirstThunk);
            UInt32 RVAOfFirstThunk = RAWToRVA(OriginalFirstThunk);
            UInt32 RVAOfOffsetOfNew_IID = RAWToRVA(offsetOfNew_IID);

            _IMPORT_DIRECTORY.Size += 0x14;
            _IMPORT_DIRECTORY.VirtualAddress = RVAOfOffsetOfNew_IID;


            if (_b32 == true)
            {
                index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 128;
            }
            else
            {
                index = Convert.ToInt32(_DOS_HEADER.e_lfanew) + 144;
            }

            File.Seek(index, 0);
            WriteType<IMAGE_DATA_DIRECTORY>(ref _IMPORT_DIRECTORY);

            File.Seek(offsetOfOriginalFirstThunk, 0);
            WriteType<UInt32>(ref RVAOfOrignalFirstThunk);
            File.Seek(offsetOfFirstThunk, 0);
            WriteType<UInt32>(ref RVAOfFirstThunk);
            File.Seek(offsetOfDLLName, 0);
            byte[] bytes = Encoding.ASCII.GetBytes(DllName);
            File.Write(bytes);
            File.Seek(offsetOfIMAGE_IMPORT_BY_NAME + 2, 0);
            bytes = Encoding.ASCII.GetBytes(FuncName);
            File.Write(bytes);
            IMAGE_IMPORT_DESCRIPTOR IID;
            File.Seek(offsetOfNew_IID, 0);
            IID.OriginalFirstThunk = RVAOfOffsetOriginalFirstThunk;
            IID.FirstThunk = RVOffsetOfFirstThunk;
            IID.Name = RVAOffsetOfDllName;
            IID.ForwarderChain = 0;
            IID.TimeDateStamp = 0;
            _IMPORT_TABLE.Add(IID);
            IMAGE_IMPORT_DESCRIPTOR tmp;
            for (int i = 0; i < _IMPORT_TABLE.Count; i++)
            {
                tmp = _IMPORT_TABLE[i];
                if(tmp.FirstThunk == 0  && tmp.OriginalFirstThunk == 0)
                {
                    continue;
                }
                WriteType<IMAGE_IMPORT_DESCRIPTOR>(ref tmp);
            }
            File.Close();
        }
        private UInt32 GetAlignedSize(UInt32 Size, UInt32 Alignment)
        {
            double flSize = Convert.ToDouble(Size);
            if(flSize%Alignment != 0)
            {
                return (Size / Alignment + 1) * Alignment;
            }
            else
            {
                return Size/Alignment * Alignment;
            }
        }
        private void WriteType<T>(ref T type)
        {
            Byte[] arr = TypeToByte<T>(ref type);
            File.Write(arr);
        }
        #endregion
    }
}
