//////////////////////////////////////////////////////////////////////////
// Nottext Software-Protection v1.7
// Writed by: Dimas Pereira
// From: Nottext Security
//////////////////////////////////////////////////////////////////////////

using Microsoft.CSharp;
using Microsoft.Win32;
using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Nottext_Software_Protection
{
    public class NottextProtection
    {
        /// <summary>
        /// Chave para a criptografia e descriptografia
        /// </summary>
        public static string EncryptionKey = "SdhMtb1GZYiClbNNjd4Yh0lqNiSrHYPa1xnlOern3Pqfr4sQYmp6dRmr05Z7SpXKcAwrfdUZtB4c6mtTPZPtq2bgy1eHg2R93EqYhBxRDqt9TdSk3jTjbwGPmkXJcoIUtztR1hj4OT4jyNKqxfPOQXe481DagLwPBgh2EHxSbr3O5D5riL6zjbshRw8z8tE9Qm2UtpnLXgaRkWAIi78HYqoqdnfcYkboMT979nIWKjou6p4em2mBjRrD5NfSy78BR79QlInxrRio7cIkUwl4DT88heRWbPYsNYA0gnmO6L33oCe9yF41a";

        /// <summary>
        /// Valores NT.
        /// </summary>
        public enum NtStatus : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }

        /// <summary>
        /// Classe de informações, usados para detectar depuradores no kernel
        /// </summary>
        private class Informations : NottextProtection
        {
            /// <summary>
            /// Informações de processos
            /// </summary>
            public enum PROCESSINFOCLASS : int
            {
                ProcessBasicInformation, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
                ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
                ProcessIoCounters, // q: IO_COUNTERS
                ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
                ProcessTimes, // q: KERNEL_USER_TIMES
                ProcessBasePriority, // s: KPRIORITY
                ProcessRaisePriority, // s: ULONG
                ProcessDebugPort, // q: HANDLE
                ProcessExceptionPort, // s: HANDLE
                ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
                ProcessLdtInformation, // 10
                ProcessLdtSize,
                ProcessDefaultHardErrorMode, // qs: ULONG
                ProcessIoPortHandlers, // (kernel-mode only)
                ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
                ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
                ProcessUserModeIOPL,
                ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
                ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
                ProcessWx86Information,
                ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
                ProcessAffinityMask, // s: KAFFINITY
                ProcessPriorityBoost, // qs: ULONG
                ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
                ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
                ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
                ProcessWow64Information, // q: ULONG_PTR
                ProcessImageFileName, // q: UNICODE_STRING
                ProcessLUIDDeviceMapsEnabled, // q: ULONG
                ProcessBreakOnTermination, // qs: ULONG
                ProcessDebugObjectHandle, // 30, q: HANDLE
                ProcessDebugFlags, // qs: ULONG
                ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
                ProcessIoPriority, // qs: ULONG
                ProcessExecuteFlags, // qs: ULONG
                ProcessResourceManagement,
                ProcessCookie, // q: ULONG
                ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
                ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
                ProcessPagePriority, // q: ULONG
                ProcessInstrumentationCallback, // 40
                ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
                ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
                ProcessImageFileNameWin32, // q: UNICODE_STRING
                ProcessImageFileMapping, // q: HANDLE (input)
                ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
                ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
                ProcessGroupInformation, // q: USHORT[]
                ProcessTokenVirtualizationEnabled, // s: ULONG
                ProcessConsoleHostProcess, // q: ULONG_PTR
                ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
                ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
                ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
                ProcessDynamicFunctionTableInformation,
                ProcessHandleCheckingMode,
                ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
                ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
                ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
                ProcessHandleTable, // since WINBLUE
                ProcessCheckStackExtentsMode,
                ProcessCommandLineInformation, // 60, q: UNICODE_STRING
                ProcessProtectionInformation, // q: PS_PROTECTION
                MaxProcessInfoClass
            }

            /// <summary>
            /// Informações do Debug
            /// </summary>
            [Flags]
            public enum DebugObjectInformationClass : int
            {
                DebugObjectFlags = 1,
                MaxDebugObjectInfoClass
            }

            /// <summary>
            /// Informações do sistema
            /// </summary>
            public enum SYSTEM_INFORMATION_CLASS
            {
                SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
                SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
                SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
                SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
                SystemPathInformation, // not implemented
                SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
                SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
                SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
                SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
                SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
                SystemCallTimeInformation, // 10, not implemented
                SystemModuleInformation, // q: RTL_PROCESS_MODULES
                SystemLocksInformation,
                SystemStackTraceInformation,
                SystemPagedPoolInformation, // not implemented
                SystemNonPagedPoolInformation, // not implemented
                SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
                SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
                SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
                SystemVdmInstemulInformation, // q
                SystemVdmBopInformation, // 20, not implemented
                SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
                SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
                SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
                SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
                SystemFullMemoryInformation, // not implemented
                SystemLoadGdiDriverInformation, // s (kernel-mode only)
                SystemUnloadGdiDriverInformation, // s (kernel-mode only)
                SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
                SystemSummaryMemoryInformation, // not implemented
                SystemMirrorMemoryInformation, // 30, s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege)
                SystemPerformanceTraceInformation, // s
                SystemObsolete0, // not implemented
                SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
                SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
                SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
                SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
                SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
                SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
                SystemPrioritySeperation, // s (requires SeTcbPrivilege)
                SystemVerifierAddDriverInformation, // 40, s (requires SeDebugPrivilege)
                SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
                SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
                SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
                SystemCurrentTimeZoneInformation, // q
                SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
                SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
                SystemSessionCreate, // not implemented
                SystemSessionDetach, // not implemented
                SystemSessionInformation, // not implemented
                SystemRangeStartInformation, // 50, q
                SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
                SystemVerifierThunkExtend, // s (kernel-mode only)
                SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
                SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
                SystemNumaProcessorMap, // q
                SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
                SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
                SystemRecommendedSharedDataAlignment, // q
                SystemComPlusPackage, // q; s
                SystemNumaAvailableMemory, // 60
                SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
                SystemEmulationBasicInformation, // q
                SystemEmulationProcessorInformation,
                SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
                SystemLostDelayedWriteInformation, // q: ULONG
                SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
                SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
                SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
                SystemHotpatchInformation, // q; s
                SystemObjectSecurityMode, // 70, q
                SystemWatchdogTimerHandler, // s (kernel-mode only)
                SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
                SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
                SystemWow64SharedInformationObsolete, // not implemented
                SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
                SystemFirmwareTableInformation, // not implemented
                SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
                SystemVerifierTriageInformation, // not implemented
                SystemSuperfetchInformation, // q: SUPERFETCH_INFORMATION; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
                SystemMemoryListInformation, // 80, q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege)
                SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
                SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
                SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
                SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
                SystemProcessorPowerInformationEx, // not implemented
                SystemRefTraceInformation, // q; s // ObQueryRefTraceInformation
                SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
                SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
                SystemErrorPortInformation, // s (requires SeTcbPrivilege)
                SystemBootEnvironmentInformation, // 90, q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION
                SystemHypervisorInformation, // q; s (kernel-mode only)
                SystemVerifierInformationEx, // q; s
                SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
                SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
                SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
                SystemPrefetchPatchInformation, // not implemented
                SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
                SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
                SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
                SystemProcessorPerformanceDistribution, // 100, q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION
                SystemNumaProximityNodeInformation, // q
                SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
                SystemCodeIntegrityInformation, // q // SeCodeIntegrityQueryInformation
                SystemProcessorMicrocodeUpdateInformation, // s
                SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
                SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
                SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
                SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
                SystemStoreInformation, // q; s // SmQueryStoreInformation
                SystemRegistryAppendString, // 110, s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS
                SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
                SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
                SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
                SystemNativeBasicInformation, // not implemented
                SystemSpare1, // not implemented
                SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
                SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
                SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
                SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
                SystemSystemPtesInformationEx, // 120, q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes)
                SystemNodeDistanceInformation, // q
                SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
                SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
                SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
                SystemSessionBigPoolInformation, // since WIN8
                SystemBootGraphicsInformation,
                SystemScrubPhysicalMemoryInformation,
                SystemBadPageInformation,
                SystemProcessorProfileControlArea,
                SystemCombinePhysicalMemoryInformation, // 130
                SystemEntropyInterruptTimingCallback,
                SystemConsoleInformation,
                SystemPlatformBinaryInformation,
                SystemThrottleNotificationInformation,
                SystemHypervisorProcessorCountInformation,
                SystemDeviceDataInformation,
                SystemDeviceDataEnumerationInformation,
                SystemMemoryTopologyInformation,
                SystemMemoryChannelInformation,
                SystemBootLogoInformation, // 140
                SystemProcessorPerformanceInformationEx, // since WINBLUE
                SystemSpare0,
                SystemSecureBootPolicyInformation,
                SystemPageFileInformationEx,
                SystemSecureBootInformation,
                SystemEntropyInterruptTimingRawInformation,
                SystemPortableWorkspaceEfiLauncherInformation,
                SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
                SystemKernelDebuggerInformationEx,
                SystemBootMetadataInformation, // 150
                SystemSoftRebootInformation,
                SystemElamCertificateInformation,
                SystemOfflineDumpConfigInformation,
                SystemProcessorFeaturesInformation,
                SystemRegistryReconciliationInformation,
                SystemEdidInformation,
                MaxSystemInfoClass
            }

            /// <summary>
            /// Informações de threads
            /// </summary>
            public enum ThreadInformationClass
            {
                ThreadBasicInformation = 0,
                ThreadTimes = 1,
                ThreadPriority = 2,
                ThreadBasePriority = 3,
                ThreadAffinityMask = 4,
                ThreadImpersonationToken = 5,
                ThreadDescriptorTableEntry = 6,
                ThreadEnableAlignmentFaultFixup = 7,
                ThreadEventPair_Reusable = 8,
                ThreadQuerySetWin32StartAddress = 9,
                ThreadZeroTlsCell = 10,
                ThreadPerformanceCount = 11,
                ThreadAmILastThread = 12,
                ThreadIdealProcessor = 13,
                ThreadPriorityBoost = 14,
                ThreadSetTlsArrayAddress = 15,   // Obsolete
                ThreadIsIoPending = 16,
                ThreadHideFromDebugger = 17,
                ThreadBreakOnTermination = 18,
                ThreadSwitchLegacyState = 19,
                ThreadIsTerminated = 20,
                ThreadLastSystemCall = 21,
                ThreadIoPriority = 22,
                ThreadCycleTime = 23,
                ThreadPagePriority = 24,
                ThreadActualBasePriority = 25,
                ThreadTebInformation = 26,
                ThreadCSwitchMon = 27,   // Obsolete
                ThreadCSwitchPmu = 28,
                ThreadWow64Context = 29,
                ThreadGroupInformation = 30,
                ThreadUmsInformation = 31,   // UMS
                ThreadCounterProfiling = 32,
                ThreadIdealProcessorEx = 33,
                ThreadCpuAccountingInformation = 34,
                ThreadSuspendCount = 35,
                ThreadDescription = 38,
                ThreadActualGroupAffinity = 41,
                ThreadDynamicCodePolicy = 42,
            }

            /// <summary>
            /// Acessos de threads
            /// </summary>
            [Flags]
            public enum ThreadAccess : int
            {
                TERMINATE = (0x0001),
                SUSPEND_RESUME = (0x0002),
                GET_CONTEXT = (0x0008),
                SET_CONTEXT = (0x0010),
                SET_INFORMATION = (0x0020),
                QUERY_INFORMATION = (0x0040),
                SET_THREAD_TOKEN = (0x0080),
                IMPERSONATE = (0x0100),
                DIRECT_IMPERSONATION = (0x0200)
            }

            /// <summary>
            /// Informações de kernel
            /// </summary>
            [StructLayout(LayoutKind.Sequential)]
            public struct SYSTEM_KERNEL_DEBUGGER_INFORMATION
            {
                [MarshalAs(UnmanagedType.U1)]
                public bool KernelDebuggerEnabled;

                [MarshalAs(UnmanagedType.U1)]
                public bool KernelDebuggerNotPresent;
            }
        }

        /// <summary>
        /// Aqui e a localização do executável onde vamos ser
        /// Carregados
        /// </summary>
        readonly static string location = Assembly.GetEntryAssembly().Location;

        /// <summary>
        /// Esta lista contém as DLL que são permitidas serem carregadas
        /// No processo
        /// </summary>
        static string dllsPermitidas = null;

        /// <summary>
        /// Data de expiração da proteção
        /// </summary>
        readonly static DateTime expiration = new DateTime(
            2021, // Ano
            12, // Mês
            30 // Dia
        );

        /// <summary>
        /// Esse arquivo vai conter o código C# para ser executado na memoria
        /// Ele verifica o hash do arquivo, e sai caso seja modificado
        /// </summary>
        readonly static string keyFile = AppDomain.CurrentDomain.BaseDirectory + "\\.key";

        /// <summary>
        /// Obtem somente o nome do arquivo executável
        /// Sem extensão
        /// </summary>
        readonly static string FileName = Path.GetFileNameWithoutExtension(location);

        /// <summary>
        /// Contém a última vez que o arquivo foi compilado
        /// PRECISA SER ALTERADO SEMPRE QUE COMPILAR O PROGRAMA
        /// DIA / MÊS / ANO (ANO = 19, 20 OU 21)
        /// </summary>
        readonly static string compilated = "23/01/21";

        /// <summary>
        /// Verifique se é necessário fazer as verificações de anti-cheat
        /// </summary>
        readonly static bool AntiCheat = false;

        /// <summary>
        /// Lista de todos os programas depuradores
        /// </summary>
        readonly static string[] DebuggersNames = {
            "x32dbg",
            "x64dbg",
            "OllyDbg",
            "ida",
            "ida64",
            "ida -",
            "ida64 -",
            "IMMUNITYDEBUGGER",
            "codecracker",
            "x96dbg",
            "de4dot",
            "ilspy",
            "graywolf",
            "die",
            "simpleassemblyexplorer",
            "megadumper",
            "x64netdumper",
            "hxd",
            "petools",
            "protection_id",
            "charles",
            "dnspy",
            "simpleassembly",
            "peek",
            "httpanalyzer",
            "httpdebug",
            "fiddler",
            "wireshark",
            "proxifier",
            "mitmproxy",
            "processhacker",
            "memoryedit",
            "memoryscanner",
            "memory scanner"
        };

        /// <summary>
        /// Lista de todos os programas que são usados no cheat
        /// </summary>
        readonly static string[] CheatersName = {
            "Cheat Engine",
            "Dev-C++",
            "Process Monitor",
            "Detect It Easy",
            //"Visual Studio",
            "Process Hacker2"
        };

        /// <summary>
        /// Cria um alerta com MessageBox
        /// </summary>
        private static void NotifyMessage(
            string msg // Mensagem que vai aparecer
        )
        {
            // Mostre a MessageBox
            System.Windows.Forms.MessageBox.Show(
                msg, // Mensagem principal
                "Nottext Software Protection", // Titulo
                System.Windows.Forms.MessageBoxButtons.OK, // Botão de OK
                System.Windows.Forms.MessageBoxIcon.Error // Icone de erro
            );
        }

        /// <summary>
        /// Mensagem de aplicativo crackeado
        /// </summary>
        private static void Cracked(string msg)
        {
            // MessageBox
            //NotifyMessage("Algum arquivo do aplicativo foi modificado, considere obter novamente este aplicativo via seu fornecedor oficial, este não funcionará mais.");

            NotifyMessage(msg + ".\r\nO programa sairá agora");

            // Saia
            Environment.Exit(0);

            // Se a chamada do Enviroment.Exit falhar, então, force 
            // A saida
            Process.GetCurrentProcess().Kill();

            // Ok, se os dois falharem, então, cause um erro sem o try
            // Catch, que o programa vai sair
            File.Create("a??|\\\\????@@1!:").Close();

            // Se nenhum desses adiantar, vamos colocar um while true
            // Para impedir a execução do aplicativo
            while (true)
            {
                // Não precisamos fazer nada
            }

            // Certo, se o while for passado para trás, vamos travar o PC
            BSOD.CauseBSOD();
        }

        /// <summary>
        /// Proteção de DLL, ele verifica repetidamente as DLLS
        /// Que estão no arquivo para ver se elas são autenticas
        /// </summary>
        private static void DllProtection()
        {
            // Novo thread, para que a DLL não fique esperando esta operação
            // Acabar para continuar a próxima
            new Thread(async () =>
            {
                // Vamos pegar o local da nossa DLL
                string location = Assembly.GetExecutingAssembly().Location;

                // Repetição infinita
                while (true)
                {
                    await Task.Delay(5000);

                    // Ok, vamos aguarde um pouco antes
                    try
                    {
                        // Lista onde vai conter todas as DLLS do processo
                        ProcessModuleCollection ObjModules = Process.GetCurrentProcess().Modules;

                        // Vamos usar ele mais tarde para comparar
                        string todasDlls = null;

                        // Procure DLL por DLL
                        foreach (ProcessModule objModule in ObjModules)
                        {
                            try
                            {
                                // Adicione o valor á string
                                todasDlls += objModule.FileName.ToLower();
                            }
                            catch (Exception) { }
                        }

                        // Se a lista de DLL estiver nulo
                        if (dllsPermitidas == null)
                            dllsPermitidas = todasDlls; // Altere o valor

                        // Agora, vamos verificar se a string é igual a de 
                        // lista de DLLS permitidas, pois se a string "dllNoProcessoString"
                        // for diferente da lista de DLL permitida, foi injetado uma DLL
                        if (dllsPermitidas.ToLower() != todasDlls && false == false)
                        {
                            // Saia do aplicativo
                            Cracked("Alguma DLL desconhecida foi injetada no processo");
                        }
                    }
                    catch (Exception) { }
                }
            }).Start();

        }

        /// <summary>
        /// Checka se o mês da assinatura já acabou
        /// </summary>
        private static bool Expiration()
        {
            // Valor para retornar
            bool returnBool = false;

            try
            {
                // Verificação falsa
                if (1 == 1)
                {
                    // Checke se já expirou
                    if (DateTime.Now > expiration)
                    {
                        // Retorne true
                        returnBool = true;
                    }
                }
                // Valores modificados, saia
                else
                {
                    Cracked("Um valor específico foi modificado");
                }
            }
            catch (Exception)
            {
                //  Mostrar a mensagem de erro
                Cracked("Não foi possível verificar a data de validação do software");
            }

            // Retorne o valor
            return returnBool;
        }

        /// <summary>
        /// Fazer uma função para checkar se está conectado
        /// Á alguma proxy
        /// </summary>
        private static void IsConnectedToProxy()
        {
            // Ok, agora vamos abrir uma pasta do regedit
            RegistryKey key = Registry.CurrentUser.OpenSubKey(
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", // Local
                false // Falso, pois só queremos ler
            );

            // Obtenha o valor para saber se há alguma proxy ativa
            string ProxyEnabledOrNo = key.GetValue("ProxyEnable").ToString();

            // Verificação falsa
            if (true == true)
            {
                // Se tiver alguma proxy ativada
                if (ProxyEnabledOrNo == "1")
                {
                    // Aplicativo está crackeado
                    Cracked("Uma proxy ativa foi detectada no sistema, por favor, desative-a e tente novamente");
                }
            }
            else
            {
                // Valor foi alterado, saia
                Cracked("Não foi possível verificar a existência de proxy");
            }
        }

        /// <summary>
        /// Essa função vai chamar as operações ManagementObjectSearcher
        /// Obter os valores e retornar
        /// </summary>
        private static string ManagementObjectSearch(
            string search, // Em qual função e pra procurar
            string especify // E a principal
        )
        {
            // String que vai ser retornada
            string stringReturn = "UNABLE TO OBTAIN";

            try
            {
                // Vai obter os valores que a DLL deseja
                ManagementObjectSearcher values = new ManagementObjectSearcher(search);

                // Agora, procura todos os valores
                foreach (ManagementObject objects in values.Get())
                {
                    // Agora, obtenha todos os valores que queremos
                    stringReturn = objects[especify].ToString();
                }
            }
            catch (Exception) { }

            // Retorne a string
            return stringReturn;
        }

        /// <summary>
        /// Essa função executa as funções apartir de um arquivo
        /// </summary>
        private static void ExecuteCodeFromFile(
            string text // Texto para executar
        )
        {
            // Novo provedor de código CSharp
            CSharpCodeProvider codeProvider = new CSharpCodeProvider();

            // Novo compilador de parametros
            CompilerParameters parameters = new CompilerParameters();

            // Agora, vamos adicionar as referencias ao código, para que
            // Ele seja executado normalmente
            parameters.ReferencedAssemblies.Add("System.Drawing.dll");
            parameters.ReferencedAssemblies.Add("System.IO.dll");
            parameters.ReferencedAssemblies.Add("System.Windows.Forms.dll");

            // Verdadeiro - geração de memória, falso - geração de arquivo externo
            // Se selecionar true, ele vai gerar na memória, se naõ, ele vai salvar
            // Em um arquivo
            parameters.GenerateInMemory = true;

            // Se for true, ele vai gerar um executável, se não, uma DLL
            parameters.GenerateExecutable = true;

            // Vamos compilar, e receber os resultados
            CompilerResults results =

                // Compilar apartir do código
                codeProvider.CompileAssemblyFromSource(
                    // Os parametros, lembra que configuramos ele?
                    parameters,

                    // Código fonte
                    text
            );

            // Vamos verificar se ocorreu algum erro
            if (results.Errors.HasErrors)
            {
                // Vamos sair, pois ocorreu um erro ao executar o comando
                Cracked("Ocorreu um erro durante a compilação do código do arquivo");

                // Novo StringBuilder, vamos usar ele já já
                StringBuilder stringBuilder = new StringBuilder();

                // Agora, vamos procurar os erros
                foreach (CompilerError error in results.Errors)
                {
                    // Vamos adicionar os erros ao StringBuilder
                    stringBuilder.AppendLine(

                        // Formato
                        String.Format("Error ({0}): {1}",

                        // Número do erro
                        error.ErrorNumber,

                        // Texto do erro
                        error.ErrorText
                   ));
                }

                System.Windows.Forms.MessageBox.Show(stringBuilder.ToString());

                // Agora, vamos adicionar uma exeção
                throw new InvalidOperationException(stringBuilder.ToString());
            }

            // Vamos obter o assmebly apartir da compilação Assembly
            Assembly assembly = results.CompiledAssembly;

            // Obtenha a classe do arquivo, exemplo: namespace First, depois dele
            // O Program {}
            Type program = assembly.GetType("First.Program");

            // Obtenha a função para ser executada, ele vai chamar a função Main()
            MethodInfo main = program.GetMethod("Main");

            // Agora, vamos executar o código
            main.Invoke(null, null);
        }

        /// <summary>
        /// Vai conter todas as operações de criptografia
        /// </summary>
        private class Cryptography : NottextProtection
        {
            // Bytes que vamos usar na criptografia
            static byte[] bytesToUse = { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 };

            /// <summary>
            /// Função para fazer criptografia
            /// </summary>
            public static string Encrypt(
                string text, // Texto para criptografar
                string password // Senha para fazer a criptografia
            )
            {
                // Obtenha os bytes do texto
                byte[] bytes = Encoding.Unicode.GetBytes(text);

                // Vamos criar uma nova criptografia
                Aes encryptor = Aes.Create();

                // Novo Rfc2898DeriveBytes
                Rfc2898DeriveBytes GetEncryptorKey = new Rfc2898DeriveBytes(
                    // Chave de criptografia
                    password,

                    // Os bytes de criptografia
                    bytesToUse
                );

                // Vamos obter os bytes do GetEncryptorKey
                encryptor.Key = GetEncryptorKey.GetBytes(32);
                encryptor.IV = GetEncryptorKey.GetBytes(16);

                // Novo MemoryStream
                MemoryStream memoryStream = new MemoryStream();

                // Novo CryptoStream
                CryptoStream cryptoStream = new CryptoStream(
                    // Vamos usa-ló
                    memoryStream,

                    // Vamos criar uma criptografia
                    encryptor.CreateEncryptor(),

                    // Modo de escrita
                    CryptoStreamMode.Write
                );

                // Vamos escrever o cryptoStream
                cryptoStream.Write(bytes, 0, bytes.Length);

                // Agora, feche-o
                cryptoStream.Close();

                // Ok, vamos criptografar o texto que nós foi passado
                text = Convert.ToBase64String(memoryStream.ToArray());

                // Agora, retorne o texto
                return text;
            }

            /// <summary>
            /// Função para fazer a descriptografia
            /// </summary>
            public static string Decrypt(
                string text, // Texto para criptografar
                string password // Senha para fazer a descriptografia
            )
            {
                // Vamos substituir alguns caracteres
                text = text.Replace(" ", "+");

                // Obtenha a string pelo texto
                byte[] bytes = Convert.FromBase64String(text);

                // Crie um novo cryptor
                Aes encryptor = Aes.Create();

                // Novo Rfc2898DeriveBytes
                Rfc2898DeriveBytes GetEncryptorKey = new Rfc2898DeriveBytes(
                    // Chave da descriptografia
                    password,

                    // Os bytes de criptografia
                    bytesToUse
                );

                // Vamos obter os bytes do GetEncryptorKey
                encryptor.Key = GetEncryptorKey.GetBytes(32);
                encryptor.IV = GetEncryptorKey.GetBytes(16);

                // Novo MemoryStream
                MemoryStream memoryStream = new MemoryStream();

                // Novo CryptoStream
                CryptoStream cryptoStream = new CryptoStream(
                    // Vamos usa-ló
                    memoryStream,

                    // Vamos criar uma descriptografia
                    encryptor.CreateDecryptor(),

                    // Modo de escrita
                    CryptoStreamMode.Write
                );

                // Agora, escreva no CryptoStream
                cryptoStream.Write(bytes, 0, bytes.Length);

                // Feche-ó
                cryptoStream.Close();

                // Agora, altere o texto para que possamos retornar
                text = Encoding.Unicode.GetString(memoryStream.ToArray());

                // Retorne o texto descriptografado
                return text;
            }

        }

        /// <summary>
        /// Aqui vai conter todas as técnicas de detecção de depuraçãos
        /// </summary>
        private class DebuggerDetectionsTechniques : NottextProtection
        {
            /// <summary>
            /// Anti-depurador no user-mode
            /// </summary>
            public class UserMode : NottextProtection
            {
                /// <summary>
                /// Importação de DLL para verificar se estamos sendo depurado
                /// </summary>
                [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
                static extern bool CheckRemoteDebuggerPresent(
                    IntPtr hProcess, // Processo para verificar
                    ref bool isDebuggerPresent // Vamos anotar o resultado aqui
                );

                /// <summary>
                /// Função que procura todos os processos filhos de um processo
                /// </summary>
                private static int ProcessAndChildren(
                    int pid // PID do processo para escanear
                )
                {
                    // Valor para retornar
                    int child = 0;

                    // Obtenha todos os processos do PID
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                        // Código
                        "Select * From Win32_Process Where ParentProcessID=" + pid
                    );

                    // Obtenha todos os valores
                    ManagementObjectCollection moc = searcher.Get();

                    // Agora, procure valor por valor
                    foreach (ManagementObject mo in moc)
                    {
                        // Processo filho dele
                        child = Convert.ToInt32(mo["ProcessID"]);
                    }

                    // Retorne o processo filho
                    return child;
                }

                /// <summary>
                /// Detecta se o x64dbg está instalado por uma chave no regedit
                /// </summary>
                private static void DetectDebuggerInstalledFromRegedit()
                {
                    // Novo registro
                    RegistryKey key;

                    // Abra essa pasta, onde tem os "ContextMenu"
                    key = Registry.ClassesRoot.OpenSubKey("\\dllfile\\shell\\", false);

                    // Agora, obtenha todos os valores
                    foreach (string values in key.GetSubKeyNames())
                    {
                        // Se conter alguma coisa com Debug, sinigifica que ele possui
                        // O x64dbg instalado ou outro programa
                        if (values.ToLower().Contains("debug"))
                        {
                            Environment.Exit(0);
                        }
                    }
                }

                /// <summary>
                /// Matar um processo Debug através de um arquivo BAT
                /// </summary>
                private async static void KillDebugger()
                {
                    // Novo Random, iremos usar logo
                    Random rd = new Random();

                    // Nome do arquivo, com um número aleatorio, para impedir que neguem
                    // O acesso
                    string tempFile = Path.GetTempPath() + "!!aaa" + rd.Next(0, 5000) + ".bat";

                    // Primeiramente, vamos criar um arquivo
                    File.WriteAllText(tempFile, "");
                    
                    // Espere um pouco, porque pode dar erro
                    await Task.Delay(100);

                    // Procure todos os nomes de depuradores
                    foreach (string line in DebuggersNames)
                    {
                        try
                        {
                            // Agora, adicione uma linha, dizendo para finalizar os processos
                            // Depuradores
                            File.AppendAllText(
                                // Arquivo
                                tempFile,

                                // Código
                                "taskkill /f /pid " + '"' + line + ".exe" + '"' +
                                Environment.NewLine
                            );
                        } catch (Exception) { }
                    }

                    // Agora, adicione o comando para ele mesmo se deletar
                    File.AppendAllText(
                        // Arquivo
                        tempFile,

                        // Código
                        "del /f /q " + '"' + tempFile + '"' + Environment.NewLine
                    );

                    // Novo processo
                    Process pp = new Process();

                    // Local do arquivo
                    pp.StartInfo.FileName = tempFile;
                    pp.StartInfo.Arguments = "";

                    // Sem janela, faça isso em segundo plano
                    pp.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;

                    // Inicie o programa
                    pp.Start();

                    // Espere o programa sair
                    pp.WaitForExit();

                    // Agora, delete o arquivo
                    File.Delete(tempFile);
                }

                /// <summary>
                /// Verifica se o nosso processo foi iniciado pelo explorer.exe
                /// Isso impede extensões como ScyllaHide.
                /// </summary>
                private static void StartedFromExplorer()
                {
                    // Quantidade de vezes em que achou um processo com o nome
                    // Explorer.exe, isso pode ser usado para burlar a proteção
                    int explorerInt = 0;

                    // Procure todos os processos na máquina
                    foreach (Process process in Process.GetProcesses())
                    {
                        // Se o nome do processo for explorer
                        if (process.ProcessName == "explorer")
                            explorerInt++; // Adicione um valor
                    }

                    // Verificação falsa
                    if (true != true)
                    {
                        // Valor alterado, saia
                        Cracked("Um valor específico foi modificado");
                    }
                    // Continue
                    else
                    {
                        // Se conter mais de um processo com o nome explorer
                        if (explorerInt > 1 && true == true)
                        {
                            // Saia
                            Cracked("Não foi possível detectar o processo confiável");
                        }
                    }

                    // Processo do explorer
                    Process explorer = Process.GetProcessesByName("explorer")[0];

                    // Agora, verifique os processo filhos dele
                    int pid = ProcessAndChildren(explorer.Id);

                    if (
                        // Verificação falsa
                        true == true
                    )
                    {
                        // Se o processo filho for diferente do processo atual
                        if (pid != Process.GetCurrentProcess().Id)
                        {
                            // Saia
                            Cracked("O programa não foi iniciado apartir de um processo confiável");
                        }
                    }

                    // Valor foi modificado
                    else
                    {
                        // Saia
                        Cracked("Um valor específico foi modificado");
                    }
                }

                /// <summary>
                /// Verifica se o aplicativo está sendo depurado (user-mode)
                /// </summary>
                public static void AntiDebugger()
                {
                    // Vamos salvar o valor depois nesta variavel
                    bool isDebugger = false;

                    // Se está sendo debugado (falso, esse valor não faz nada)
                    bool isDebugging = false;

                    // Verifique se estamos sendo deuprado
                    CheckRemoteDebuggerPresent(
                        Process.GetCurrentProcess().Handle, // Nosso processo
                        ref isDebugger // Salve aqui
                    );

                    // Vamos verificar se alguém está depurando o nosso programa
                    if (
                        isDebugger == true ||

                        // Outra maneira de verificar se está sendo depurado
                        Debugger.IsAttached ||

                        // Faz uma verificação falsa, se ele for true
                        // Significa que o engenheiro reverso modificou o valor
                        isDebugging == true ||

                        // Outra maneira de verificar o debugger
                        Debugger.IsLogging()

                    )
                    {
                        // Sabemos que se o código chegou até aqui
                        // E porque ele detectou um depurador.

                        // Agora, vamos fazer algumas verificações falsas no nosso
                        // Código, para dificultar ainda mais a vida do cracker.

                        // ????
                        if (1 != 1)
                        {
                            // Mais uma verificação inutil kkk
                            if (55 * 65 != 45 || 1 * 2 == 5)
                            {
                                // Crackeado
                                Cracked("Um depurador foi encontrado");
                            }
                            else
                            {
                                // Se os valores forem mudados, saia
                                Cracked("Um valor específico foi modificado");
                            }
                        }

                        // Só mais um obstaculo
                        else
                        {
                            // What ?
                            if (true == true)
                            {
                                // Esta sendo debugado, temos que sair
                                Cracked("Um valor específico foi modificado");
                            }
                            else
                            {
                                // Se os valores forem mudados, saia
                                Cracked("Um valor específico foi modificado");
                            }
                        }
                    }

                    // Ok, vamos esperar matar os depuradores
                    KillDebugger();

                    // Escapar de extensões que ocultam depuradores
                    StartedFromExplorer();
                }

                /// <summary>
                /// Importação da DLL para saber se o processo foi alterado
                /// </summary>
                [DllImport("ntdll.dll")]
                internal static extern NtStatus NtSetInformation(
                    IntPtr ThreadHandle, // Thread do processo
                    Informations.ThreadInformationClass ThreadInformationClass, // Informação do Thread
                    IntPtr ThreadInformation, // Inforamções do Thread
                    int ThreadInformationLength // Informação do tamanho do thread
                );

                /// <summary>
                /// Importação da DLL para abrir um thread para que possa suspender
                /// O resumir, finalizar é etc
                /// </summary>
                [DllImport("kernel32.dll")]
                static extern IntPtr OpenThread(
                    Informations.ThreadAccess dwDesiredAccess, // Acesso do thread
                    bool bInheritHandle, // Saber se veio de herança 
                    uint dwThreadId // ID do Threads
                );

                /// <summary>
                /// Importação da DLL para suspender um thread
                /// </summary>
                [DllImport("kernel32.dll")]
                static extern uint SuspendThread(
                    IntPtr tThread // Thread para suspender
                );

                /// <summary>
                /// Importação da DLL para resumir um thread
                /// </summary>
                [DllImport("kernel32.dll")]
                static extern int ResumeThread(
                    IntPtr tThread // Thread para resumirs
                );

                /// <summary>
                /// Importação da DLL para fechar
                /// </summary>
                [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
                static extern bool CloseHandle(
                    IntPtr handle // Lidar com
                );

                /// <summary>
                /// Ocultar as funções no depurador
                /// </summary>
                public static bool HideFromDebugger(
                    IntPtr Handle
                )
                {
                    // Agora, vamos setar as informações no processo
                    NtStatus nStatus = NtSetInformation(
                        Handle, // O que nós foi passado
                        Informations.ThreadInformationClass.ThreadHideFromDebugger, // Ocultar
                        IntPtr.Zero, // Zero
                        0 // 0
                    );

                    // Se obter um erro, vamos sair do programa
                    if (nStatus != NtStatus.Success)
                    {
                        // Não conseguimos ocultar o thread
                        return false;
                    }

                    // Conseguimos ocultar o thread
                    return true;
                }

                /// <summary>
                /// Ocultar todos os threads do processo para impedir o depurador
                /// De nós analizar
                /// </summary>
                public static void HideOSThreads()
                {
                    // Vamos obter todos os threads do nosso programa
                    ProcessThreadCollection threadCollection = Process.GetCurrentProcess().Threads;

                    // Procure thread por thread em todos os threads do processo atual
                    foreach (ProcessThread thread in threadCollection)
                    {
                        try
                        {
                            // Agora, vamos abrir o thread
                            IntPtr pOpenThread = OpenThread(

                                // Vamos alterar informação do thread
                                Informations.ThreadAccess.SET_INFORMATION,
                                false, // Não e "herdavél"
                                (uint)thread.Id // ID do thread
                            );

                            // Se não conseguir abrir o thread
                            if (pOpenThread == IntPtr.Zero)
                            {
                                // Pule a operação atual, e continue em outra
                                continue;
                            }

                            // Agora, vamos verificar se ocorreu um erro
                            // Ao ocultar o thread
                            if (!HideFromDebugger(pOpenThread))
                            {
                                // Ocorreu um erro ao ocultar o thread
                            }

                            // Terminamos com o thread, hora de fecha-ló
                            CloseHandle(
                                pOpenThread // Thread que abrimos
                            );
                        }
                        catch (Exception) { }
                    }
                }

                /// <summary>
                /// Classe onde vai conter tudo necessário para a auto
                /// Depuração, que impede depuradores de anexarem-se ao
                /// Nosso processo, código foi pego aqui:
                /// http://csharptest.net/1051/managed-anti-debugging-how-to-prevent-users-from-attaching-a-debugger/index.html
                /// </summary>
                public class AutoDebugger : NottextProtection
                {
                    /// <summary>
                    /// Depurar tipo de evento
                    /// </summary>
                    enum DebugEventType : int
                    {
                        CREATE_PROCESS_DEBUG_EVENT = 3, //Reports a create-process debugging event. The value of u.CreateProcessInfo specifies a CREATE_PROCESS_DEBUG_INFO structure.
                        CREATE_THREAD_DEBUG_EVENT = 2, //Reports a create-thread debugging event. The value of u.CreateThread specifies a CREATE_THREAD_DEBUG_INFO structure.
                        EXCEPTION_DEBUG_EVENT = 1, //Reports an exception debugging event. The value of u.Exception specifies an EXCEPTION_DEBUG_INFO structure.
                        EXIT_PROCESS_DEBUG_EVENT = 5, //Reports an exit-process debugging event. The value of u.ExitProcess specifies an EXIT_PROCESS_DEBUG_INFO structure.
                        EXIT_THREAD_DEBUG_EVENT = 4, //Reports an exit-thread debugging event. The value of u.ExitThread specifies an EXIT_THREAD_DEBUG_INFO structure.
                        LOAD_DLL_DEBUG_EVENT = 6, //Reports a load-dynamic-link-library (DLL) debugging event. The value of u.LoadDll specifies a LOAD_DLL_DEBUG_INFO structure.
                        OUTPUT_DEBUG_STRING_EVENT = 8, //Reports an output-debugging-string debugging event. The value of u.DebugString specifies an OUTPUT_DEBUG_STRING_INFO structure.
                        RIP_EVENT = 9, //Reports a RIP-debugging event (system debugging error). The value of u.RipInfo specifies a RIP_INFO structure.
                        UNLOAD_DLL_DEBUG_EVENT = 7, //Reports an unload-DLL debugging event. The value of u.UnloadDll specifies an UNLOAD_DLL_DEBUG_INFO structure.
                    }

                    /// <summary>
                    /// Estrutura dos eventos
                    /// </summary>
                    [StructLayout(LayoutKind.Sequential)]
                    struct DebugEvent
                    {
                        [MarshalAs(UnmanagedType.I4)]
                        public DebugEventType dwDebugEventCode;
                        public int dwProcessId;
                        public int dwThreadId;
                        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
                        public byte[] bytes;
                    }

                    /// <summary>
                    /// Nova importação de DLL, para anexar o processo a um outro processo
                    /// </summary>
                    [DllImport("kernel32.dll", SetLastError = true)]
                    private static extern bool DebugActiveProcess(
                        int dwProcessId // PID
                    );

                    /// <summary>
                    /// Importação da DLL para esperar por um evento de debug
                    /// </summary>
                    [DllImport("Kernel32.dll", SetLastError = true)]
                    private static extern bool WaitForDebugEvent(
                        [Out] out DebugEvent lpDebugEvent, // Evento
                        int dwMilliseconds // Milisegundos
                    );

                    /// <summary>
                    /// Continuar o evento do debug
                    /// </summary>
                    [DllImport("Kernel32.dll", SetLastError = true)]
                    private static extern bool ContinueDebugEvent(
                        int dwProcessId, // PID
                        int dwThreadId, // Thread
                        int dwContinueStatus // Status de continuar
                    );

                    // Eventos de debug
                    const int DBG_CONTINUE = 0x00010002;
                    const int DBG_EXCEPTION_NOT_HANDLED = unchecked((int)0x80010001);

                    /// <summary>
                    /// Se mate quando o processo terminar, caso o usuário finaliza
                    /// O processo
                    /// </summary>
                    private static void KillOnExit(
                        object process // Process pra esperar
                    )
                    {
                        // O thread vai rodar em segundo plano
                        Thread.CurrentThread.IsBackground = true;

                        // Espere o processo sair
                        ((Process)process).WaitForExit();

                        // Saia
                        Environment.Exit(0);

                        // Chame a função de sair
                        Cracked("Não foi possível se auto-fechar");
                    }

                    [DllImport("Kernel32.dll", SetLastError = true)]
                    public static extern bool IsDebuggerPresent();

                    /// <summary>
                    /// Função que espera pelo depurador
                    /// </summary>
                    private static void WaitForDebugger()
                    {
                        // Tempo de agora
                        DateTime dateTime = DateTime.Now;

                        // Repetição enquanto não contem um depurador
                        while (!IsDebuggerPresent())
                        {

                            // Se o tempo em minutos for maior que um
                            if ((DateTime.Now - dateTime).TotalMinutes > 1)
                            {
                                // Saia
                                Cracked("A data correta não foi encontrada");
                            }

                            // Durma
                            Thread.Sleep(1);
                        }
                    }

                    /// <summary>
                    /// Essa função verifica o PID fornecido, se for de um arquivo
                    /// Desconhecido, que não seja o nosso arquivo, a gente
                    /// Sai do aplicativo
                    /// </summary>
                    public static void CheckPid(
                        int Pid // PID
                    )
                    {
                        // Obtenha o nome do arquivo
                        string filename = Path.GetFileNameWithoutExtension(
                            // Local do EXE
                            location
                        );

                        // Verifique se o nome do processo coresponde ao nome do arquivo
                        // Porque algum expertinho pode tentar depurar outro processo
                        // Apenas passando a linha de comando, isso preveni que outros
                        // Processos sejam depuradores
                        if (Process.GetProcessById(Pid).ProcessName != filename && true == true)
                        {
                            // Saia
                            Cracked("O processo foi modificado");
                        }
                    }

                    /// <summary>
                    /// Depura um thread
                    /// </summary>
                    private static void DebuggerThread(
                        object arg // Argumentos
                    )
                    {
                        // O thread vai rodar em segundo plano
                        Thread.CurrentThread.IsBackground = true;

                        // Novo evento
                        DebugEvent debugEvent = new DebugEvent();

                        // Tamanho dos bytes
                        debugEvent.bytes = new byte[1024];

                        // Se nenhum depurador estiver no processo
                        if (!DebugActiveProcess((int)arg))
                        {
                            // Saia do processo
                            Cracked("Um depurador foi detectado no processo ativo");
                        }

                        // Repetição infinita
                        while (true)
                        {
                            // Espere pelo evento do depurador
                            if (!WaitForDebugEvent(out debugEvent, -1))
                            {
                                // Algum valor incorreto, saia
                                Cracked("Não foi possível continuar o processo de auto-debug");
                            }

                            // Bandeira de continuação
                            int continueFlag = DBG_CONTINUE;

                            // Se o código do evento de depurador for uma exeção
                            // Altere o evento para = EXCEPTION_DEBUG_EVENT
                            if (debugEvent.dwDebugEventCode == DebugEventType.EXCEPTION_DEBUG_EVENT)
                            {
                                // Altere a bandeira
                                continueFlag = DBG_EXCEPTION_NOT_HANDLED;
                            }

                            // Continue o evento de depuração
                            ContinueDebugEvent(
                                    debugEvent.dwProcessId, // PID
                                    debugEvent.dwThreadId, // Thread
                                    continueFlag // Bandeira
                            );
                        }
                    }

                    /// <summary>
                    /// Isso gerará um processo de inspetor para monitorar um pai,
                    /// e cada pinvoke fará um thread de depuração um no outro.
                    /// Se um dos processos for eliminado (pai ou filho), os dois saem,
                    /// protegendo um ao outro de serem depurados.
                    /// </summary>
                    public static void SelfDebugger(int ppid)
                    {
                        try
                        {
                            // Se o PID for diferente de 0
                            if (ppid != 0)
                            {
                                // Pega o processo apartir do PID fornecido
                                Process getProcessPid = Process.GetProcessById(ppid);

                                // Espere a finalização do processo pra terminar
                                new Thread(KillOnExit) { IsBackground = true }.Start(getProcessPid);

                                // Espere nosso processo pai nos depurar
                                WaitForDebugger();

                                // Comece a depurar nosso processo pai
                                DebuggerThread(ppid);

                                // Tudo completo, o usuário finalizou o processo
                                // Devemos sair
                                Environment.Exit(1);
                            }

                            // Obtem o processo atual
                            Process currentProcess = Process.GetCurrentProcess();

                            // Novo ProcessStartInfo
                            ProcessStartInfo processStart = new ProcessStartInfo(
                                Environment.GetCommandLineArgs()[0], // Argumentos
                                currentProcess.Id.ToString() // ID
                            )
                            {
                                // Sem shell
                                UseShellExecute = false,

                                // Sem criar janela
                                CreateNoWindow = false,

                                // Sem dialogo de erro
                                ErrorDialog = false,
                                //WindowStyle = ProcessWindowStyle.Hidden
                            };

                            // Inicia o ProcessStartInfo
                            Process pdbg = Process.Start(processStart);

                            // Se o pdbg estiver nulo
                            if (pdbg == null)
                                throw new ApplicationException("Unable to debug");

                            // Agora, crie um novo thread
                            // E espere a finalização do processo
                            new Thread(KillOnExit) { IsBackground = true }.Start(pdbg);

                            // Depure o thread atual, ele obtem os eventos
                            // Do thread atual
                            new Thread(DebuggerThread) { IsBackground = true }.Start(pdbg.Id);

                            // Espere pelo depurador
                            WaitForDebugger();
                        }

                        // Se falahr
                        catch (Exception)
                        {
                            // Verificação falsa
                            if (1 + 5 == 6)
                            {
                                // Um depurador tentou se conectar ao aplicativo
                                // Saia
                                Cracked("Não foi possível continuar o auto-debug");
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Anti-depurador no kernel-mode
            /// </summary>
            public class KernelMode
            {
                /// <summary>
                /// Importação da DLL para obter informação do processo
                /// </summary>
                [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
                internal static extern NtStatus NtQueryInformationProcess(
                    IntPtr ProcessHandle, // Processo atual
                    Informations.PROCESSINFOCLASS ProcessInformationClass, // Informação do processo
                    out IntPtr ProcessInformation, // Informação do processo
                    int ProcessInformationLength, // Tamanho da informação do processo
                    out int ReturnLength // Tamanho para retornar
                );

                /// <summary>
                /// Importação da DLL para fechar um processo
                /// </summary>
                [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
                internal static extern NtStatus NtClose(
                    IntPtr Handle // Váriavel
                );

                /// <summary>
                /// Importação da DLL para remover o processo de um depurador
                /// </summary>
                [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
                internal static extern NtStatus NtRemoveProcessDebug(
                    IntPtr ProcessHandle, // Processo
                    IntPtr DebugObjectHandle // Depurador
                );

                /// <summary>
                /// Importação da DLL para alterar as informações de depurador
                /// </summary>
                [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
                internal static extern NtStatus NtSetInformationDebugObject(
                    IntPtr DebugObjectHandle, // Objeto de depurador

                    // Informações do depurador
                    Informations.DebugObjectInformationClass DebugObjectInformationClass,

                    // Informação do objeto do depurador
                    IntPtr DebugObjectInformation,

                    // Informação em tamanho (length)
                    int DebugObjectInformationLength,

                    // (Opicional) retornar o valor
                    [Out][Optional] out int ReturnLength
                );

                /// <summary>
                /// Importação da DLL para obter informação sobre o sistema
                /// </summary>
                /// <returns></returns>
                [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
                internal static extern NtStatus NtQuerySystemInformation(
                    // Informação da classe do sistema
                    Informations.SYSTEM_INFORMATION_CLASS SystemInformationClass,
                    IntPtr SystemInformation, // Informação do sistema
                    int SystemInformationLength, // Inforamão em tamanho

                    // (Opicional) retornar o valor
                    [Out][Optional] out int ReturnLength
                );

                // Vamos de inválido
                static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

                /// <summary>
                /// Checkar a porta de depuração
                /// </summary>
                private static bool CheckDebugPort()
                {
                    // Status
                    NtStatus status;

                    // Porta de depuração
                    IntPtr DebugPort = new IntPtr(0);

                    // Tamanho que vai retornar
                    int ReturnLength;

                    // Obter as informações do processo
                    status = NtQueryInformationProcess(
                        Process.GetCurrentProcess().Handle, // Processo atual
                        Informations.PROCESSINFOCLASS.ProcessDebugPort, // Porta de depuração
                        out DebugPort, // Salve aqui
                        Marshal.SizeOf(DebugPort), // Converta a porta de depuração
                        out ReturnLength // Valor para retornar, salve aqui
                    );

                    // Se conseguir obter as informações do processo
                    if (status == NtStatus.Success)
                    {
                        // Se haver alguma porta de depuração
                        if (DebugPort == new IntPtr(-1))
                        {
                            // Retorne verdade
                            return true;
                        }
                    }

                    // Sem porta de depuração
                    return false;
                }

                /// <summary>
                /// Desanexar o processo do depurador
                /// </summary>
                private static bool DetachFromDebuggerProcess()
                {
                    // Objeto do depurador
                    IntPtr hDebugObject = INVALID_HANDLE_VALUE;

                    // Flags
                    var Flags = 0U;

                    // Status
                    NtStatus status;

                    // Retornos em INT
                    int retLength_1;
                    int retLength_2;

                    // Vamos iniciar o código inseguro
                    unsafe
                    {

                        // Obter as informações do processo
                        // Vamos usar mais tarde
                        status = NtQueryInformationProcess(
                            Process.GetCurrentProcess().Handle, // Processo atual
                            Informations.PROCESSINFOCLASS.ProcessDebugPort, // Porta de depuração
                            out hDebugObject, // Salve aqui
                            IntPtr.Size, // Tamanho do IntPtr
                            out retLength_1 // Valor para retornar, salve aqui
                        );

                        // Se não obter a resposta de sucesso
                        if (status != NtStatus.Success)
                        {
                            // Retorne falso
                            return false;
                        }

                        // Agora que já obtemos as informações do processo
                        // Hora de verificar as propriedades do depurador

                        // Vamos setar uma configuração no objeto do depurador
                        status = NtSetInformationDebugObject(
                            hDebugObject, // Lembra dele?
                            Informations.DebugObjectInformationClass.DebugObjectFlags, // Os flags
                            new IntPtr(&Flags), // Flags
                            Marshal.SizeOf(Flags), // Realmente, não sei oq é isso
                            out retLength_2 // Vamos retornar aqui
                        );

                        // Se não conseguir alterar as propriedades
                        // Do depurador
                        if (status != NtStatus.Success)
                        {
                            // Retorne falso
                            return false;
                        }

                        // Ok, se o código chegou até aqui, significa que ele
                        // Detectou um depurador, pois conseguimos alterar
                        // As informações dele, hora de remover o processo dele

                        status = NtRemoveProcessDebug(
                            Process.GetCurrentProcess().Handle, // Processo atual
                            hDebugObject // Lembra dele?
                        );

                        // Se falhar ao remover o processo do depurador
                        if (status != NtStatus.Success)
                        {
                            // Retorne falso
                            return false;
                        }

                        // Hora de fechar o carinha
                        status = NtClose(
                            hDebugObject // Feche-o
                        );

                        // Se falhar
                        if (status != NtStatus.Success)
                        {
                            // Retorne falso
                            return false;
                        }
                    }

                    // Valor verdadeiro
                    return true;
                }

                /// <summary>
                /// Checkar as informações do depurador
                /// </summary>
                private static bool CheckKernelDebugInformation()
                {
                    // Informações do depurador
                    Informations.SYSTEM_KERNEL_DEBUGGER_INFORMATION hDebuggerInformation;

                    // Int para retornar
                    int retLength;

                    // Status
                    NtStatus status;

                    // Código não seguro
                    unsafe
                    {
                        // Vamos obter as informações do sistema
                        status = NtQuerySystemInformation(
                            // Informações sobre o depurador do kernel
                            Informations.SYSTEM_INFORMATION_CLASS.SystemKernelDebuggerInformation,
                            new IntPtr(&hDebuggerInformation), // Vamos guardar aqui
                            Marshal.SizeOf(hDebuggerInformation), // Retorne o tamanho
                            out retLength // Use esse carinha para retornar o valor
                        );

                        // Se conseguir obter as inforamções que queriamos
                        if (status == NtStatus.Success)
                        {
                            if (
                                // Se o depurador estiver habilitado
                                hDebuggerInformation.KernelDebuggerEnabled &&

                                // Se o depurador estiver presentes
                                !hDebuggerInformation.KernelDebuggerNotPresent
                                )
                            {
                                // Retorne verdade
                                return true;
                            }
                        }
                    }

                    // Falso
                    return false;
                }

                /// <summary>
                /// Detecta o debugger no kernel
                /// </summary>
                public static bool AntiDebugger()
                {
                    // Vamos verificar se há alguma porta no depurador
                    if (CheckDebugPort())
                    {
                        // Resultou em true, saia do aplicativo
                        Cracked("Uma porta de depuração foi encontrada");
                    }

                    // Agora, vamos tentar remover o processo do depurador
                    if (DetachFromDebuggerProcess())
                    {
                        // Conseguiu encontrar algo, saia do aplicativo
                        Cracked("Um depurador kernel-mode foi encontrado em um processo");
                    }

                    // Se conseguir obter as informações de qualquer
                    // Depurador
                    if (CheckKernelDebugInformation())
                    {
                        // Um depurador foi encontrado, saia
                        Cracked("Um depurador kernel-mode foi encontrado");
                    }

                    // Valor falso
                    return false;
                }
            }
        }

        /// <summary>
        /// Aqui vai conter todas as técnicas para detectar se o arquivo
        /// Foi modificados
        /// </summary>
        private class ModificationsDetectionsTechniques : NottextProtection
        {
            /// <summary>
            /// Checka o último dia que o arquivo foi modificado
            /// </summary>
            public static void LastModifiedFile()
            {
                try
                {
                    // Pega a data da última escrita do arquivo
                    var lastWrite = File.GetLastWriteTime(location);

                    // Verificação falsa
                    if (true == true)
                    {
                        // What? kk
                        if (2 * 2 == 4)
                        {
                            // Converta para a data
                            string dateLastWrite = lastWrite.ToString("dd/MM/yy");

                            // Agora, faça mais algumas verificações falsas
                            if (false != true)
                            {
                                // Agora, se a data do arquivo e diferente da data que foi
                                // Compilado
                                if (dateLastWrite != compilated)
                                {
                                    // Ok, agora, mais uma verificação falsa
                                    if (1 + 5 == 6)
                                    {
                                        // Saia do aplicativo
                                        Cracked("O arquivo foi modificado");
                                    }
                                    else
                                    {
                                        // Se os valores forem mudados, saia
                                        Cracked("Um valor específico foi modificado");
                                    }
                                }
                            }
                            else
                            {
                                // Se os valores forem mudados, saia
                                Cracked("Um valor específico foi modificado");
                            }
                        }
                        else
                        {
                            // Se os valores forem mudados, saia
                            Cracked("Um valor específico foi modificado");
                        }
                    }
                }
                catch (Exception)
                {
                    // Se ocorrer uma execeção, saia do aplicativo
                    Cracked("Ocorreu um erro ao tentar acessar a modificação");
                }
            }

            /// <summary>
            /// Verificar o hashe MD5 e está sendo debugado
            /// </summary>
            public static void MD5Protection()
            {
                // Vamos executar o código do arquivo, para verificar se nosso arquivo foi modificado
                ExecuteCodeFromFile(
                    // Por padrão, o arquivo de comando é criptografado
                    // Vamos descriptografa-ló
                    Cryptography.Decrypt(
                        // Texto do arquivo
                        File.ReadAllText(".command"),

                        // Chave padrão
                        Cryptography.EncryptionKey
                    )
                );
            }
        }

        /// <summary>
        /// Vamos por algumas técnicas para fazer o engenheiro
        /// Mais perto de fazer o desistir
        /// </summary>
        private class TrickTechniques : NottextProtection
        {
            /// <summary>
            /// Proteção de anti-programas (Tipo anti-cheat, anti-depuradores)
            /// </summary>
            public static void AntiPrograms(
                string[] lists, // Lista de nomes de programas
                int time // Tempo de intervalo
            )
            {
                // Precisamos criar um novo thread para que não ficarmos travados
                // Em um loop infinito
                new Thread(async () =>
                {
                    // Repetição infinita
                    while (true)
                    {
                        try
                        {
                            // Vamos fazer uma lista de todos os processos
                            var processes = Process.GetProcesses().ToList();

                            // Procure de processo em processo
                            foreach (Process process in processes)
                            {
                                // Não queremos causar lentidão no PC
                                // Vamos aguardar um minisegundos
                                await Task.Delay(200);

                                try
                                {
                                    // Vamos procurar todos os programas indesejado
                                    // Na lista
                                    foreach (string program in lists)
                                    {
                                        // Pega o titlo do programa
                                        string title = process.MainWindowTitle.ToLower();

                                        // Se o titlo do processo conter alguma coisa
                                        // Parecida, algum cheat foi encontrado
                                        if (title.Contains(program.ToLower()))
                                        {
                                            // Cheat encontrado, vamos sair
                                            Cracked("Um programa malicioso foi encontrado");
                                        }
                                    }

                                }
                                catch (Exception) { }
                            }
                        }
                        catch (Exception) { Environment.Exit(0); }

                        // Vamos aguardar o time
                        await Task.Delay(time);
                    }
                }).Start();
            }

            /// <summary>
            /// Função que cria um LOOP de 0 á 1000, se o engenheiro reverso quiser
            /// Analisar etapa por etapa no depurador (f8 toda hora)
            /// Ele vai esperar mil vezes para a continuação do código
            /// </summary>
            public static int AwaitLoop()
            {
                // Se é pra continuar o código
                int continueCode = 0;

                // Faça um LOOP até mil
                for (int i = 0; i < 1000; i++)
                {
                    // Adicione o valor
                    continueCode++;
                }

                // Retorne o INT
                return continueCode;
            }
        }

        /// <summary>
        /// Técnicas de VirtualProtect (Anti-Dumper), para definir alguns endereços da
        /// Memoria como somente-leitura, impedir um dumper do código e etc.
        /// Esse código foi copiado, link dentro do código:
        /// https://github.com/KNIF/Guardian/blob/master/Guardian/AntiDump.cs
        /// </summary>
        private class VirtualProtectTechniques : NottextProtection
        {
            /// <summary>
            /// Importação da DLL para o VirtualProtect
            /// </summary>
            [DllImport("kernel32.dll")]
            static extern unsafe bool VirtualProtect(
                byte* lpAddress, // Endereço
                int dwSize, // Tamanho
                uint flNewProtect, // Novo protetor
                out uint lpflOldProtect // Antigo protetor
            );

            /// <summary>
            /// Iniciar a proteção do VirtualProtect (controlar acessos de mémoria)
            /// </summary>
            internal static unsafe void InitializeVirutalProtect()
            {
                uint old;
                Module module = typeof(NottextProtection).Module;
                var bas = (byte*)Marshal.GetHINSTANCE(module);
                byte* ptr = bas + 0x3c;
                byte* ptr2;
                ptr = ptr2 = bas + *(uint*)ptr;
                ptr += 0x6;
                ushort sectNum = *(ushort*)ptr;
                ptr += 14;
                ushort optSize = *(ushort*)ptr;
                ptr = ptr2 = ptr + 0x4 + optSize;

                byte* @new = stackalloc byte[11];
                if (module.FullyQualifiedName[0] != '<') //Mapped
                {
                    //VirtualProtect(ptr - 16, 8, 0x40, out old);
                    //*(uint*)(ptr - 12) = 0;
                    byte* mdDir = bas + *(uint*)(ptr - 16);
                    //*(uint*)(ptr - 16) = 0;

                    if (*(uint*)(ptr - 0x78) != 0)
                    {
                        byte* importDir = bas + *(uint*)(ptr - 0x78);
                        byte* oftMod = bas + *(uint*)importDir;
                        byte* modName = bas + *(uint*)(importDir + 12);
                        byte* funcName = bas + *(uint*)oftMod + 2;
                        VirtualProtect(modName, 11, 0x40, out old);

                        *(uint*)@new = 0x6c64746e;
                        *((uint*)@new + 1) = 0x6c642e6c;
                        *((ushort*)@new + 4) = 0x006c;
                        *(@new + 10) = 0;

                        for (int i = 0; i < 11; i++)
                            *(modName + i) = *(@new + i);

                        VirtualProtect(funcName, 11, 0x40, out old);

                        *(uint*)@new = 0x6f43744e;
                        *((uint*)@new + 1) = 0x6e69746e;
                        *((ushort*)@new + 4) = 0x6575;
                        *(@new + 10) = 0;

                        for (int i = 0; i < 11; i++)
                            *(funcName + i) = *(@new + i);
                    }

                    for (int i = 0; i < sectNum; i++)
                    {
                        VirtualProtect(ptr, 8, 0x40, out old);
                        Marshal.Copy(new byte[8], 0, (IntPtr)ptr, 8);
                        ptr += 0x28;
                    }

                    VirtualProtect(mdDir, 0x48, 0x40, out old);
                    byte* mdHdr = bas + *(uint*)(mdDir + 8);
                    *(uint*)mdDir = 0;
                    *((uint*)mdDir + 1) = 0;
                    *((uint*)mdDir + 2) = 0;
                    *((uint*)mdDir + 3) = 0;

                    VirtualProtect(mdHdr, 4, 0x40, out old);
                    *(uint*)mdHdr = 0;
                    mdHdr += 12;
                    mdHdr += *(uint*)mdHdr;
                    mdHdr = (byte*)(((ulong)mdHdr + 7) & ~3UL);
                    mdHdr += 2;
                    ushort numOfStream = *mdHdr;
                    mdHdr += 2;
                    for (int i = 0; i < numOfStream; i++)
                    {
                        VirtualProtect(mdHdr, 8, 0x40, out old);
                        //*(uint*)mdHdr = 0;
                        mdHdr += 4;
                        //*(uint*)mdHdr = 0;
                        mdHdr += 4;
                        for (int ii = 0; ii < 8; ii++)
                        {
                            VirtualProtect(mdHdr, 4, 0x40, out old);
                            *mdHdr = 0;
                            mdHdr++;
                            if (*mdHdr == 0)
                            {
                                mdHdr += 3;
                                break;
                            }

                            *mdHdr = 0;
                            mdHdr++;
                            if (*mdHdr == 0)
                            {
                                mdHdr += 2;
                                break;
                            }

                            *mdHdr = 0;
                            mdHdr++;
                            if (*mdHdr == 0)
                            {
                                mdHdr += 1;
                                break;
                            }

                            *mdHdr = 0;
                            mdHdr++;
                        }
                    }
                }
                else //Flat
                {
                    //VirtualProtect(ptr - 16, 8, 0x40, out old);
                    //*(uint*)(ptr - 12) = 0;
                    uint mdDir = *(uint*)(ptr - 16);
                    //*(uint*)(ptr - 16) = 0;
                    uint importDir = *(uint*)(ptr - 0x78);

                    var vAdrs = new uint[sectNum];
                    var vSizes = new uint[sectNum];
                    var rAdrs = new uint[sectNum];
                    for (int i = 0; i < sectNum; i++)
                    {
                        VirtualProtect(ptr, 8, 0x40, out old);
                        Marshal.Copy(new byte[8], 0, (IntPtr)ptr, 8);
                        vAdrs[i] = *(uint*)(ptr + 12);
                        vSizes[i] = *(uint*)(ptr + 8);
                        rAdrs[i] = *(uint*)(ptr + 20);
                        ptr += 0x28;
                    }


                    if (importDir != 0)
                    {
                        for (int i = 0; i < sectNum; i++)
                            if (vAdrs[i] <= importDir && importDir < vAdrs[i] + vSizes[i])
                            {
                                importDir = importDir - vAdrs[i] + rAdrs[i];
                                break;
                            }

                        byte* importDirPtr = bas + importDir;
                        uint oftMod = *(uint*)importDirPtr;
                        for (int i = 0; i < sectNum; i++)
                            if (vAdrs[i] <= oftMod && oftMod < vAdrs[i] + vSizes[i])
                            {
                                oftMod = oftMod - vAdrs[i] + rAdrs[i];
                                break;
                            }

                        byte* oftModPtr = bas + oftMod;
                        uint modName = *(uint*)(importDirPtr + 12);
                        for (int i = 0; i < sectNum; i++)
                            if (vAdrs[i] <= modName && modName < vAdrs[i] + vSizes[i])
                            {
                                modName = modName - vAdrs[i] + rAdrs[i];
                                break;
                            }

                        uint funcName = *(uint*)oftModPtr + 2;
                        for (int i = 0; i < sectNum; i++)
                            if (vAdrs[i] <= funcName && funcName < vAdrs[i] + vSizes[i])
                            {
                                funcName = funcName - vAdrs[i] + rAdrs[i];
                                break;
                            }

                        VirtualProtect(bas + modName, 11, 0x40, out old);

                        *(uint*)@new = 0x6c64746e;
                        *((uint*)@new + 1) = 0x6c642e6c;
                        *((ushort*)@new + 4) = 0x006c;
                        *(@new + 10) = 0;

                        for (int i = 0; i < 11; i++)
                            *(bas + modName + i) = *(@new + i);

                        VirtualProtect(bas + funcName, 11, 0x40, out old);

                        *(uint*)@new = 0x6f43744e;
                        *((uint*)@new + 1) = 0x6e69746e;
                        *((ushort*)@new + 4) = 0x6575;
                        *(@new + 10) = 0;

                        for (int i = 0; i < 11; i++)
                            *(bas + funcName + i) = *(@new + i);
                    }


                    for (int i = 0; i < sectNum; i++)
                        if (vAdrs[i] <= mdDir && mdDir < vAdrs[i] + vSizes[i])
                        {
                            mdDir = mdDir - vAdrs[i] + rAdrs[i];
                            break;
                        }

                    byte* mdDirPtr = bas + mdDir;
                    VirtualProtect(mdDirPtr, 0x48, 0x40, out old);
                    uint mdHdr = *(uint*)(mdDirPtr + 8);
                    for (int i = 0; i < sectNum; i++)
                        if (vAdrs[i] <= mdHdr && mdHdr < vAdrs[i] + vSizes[i])
                        {
                            mdHdr = mdHdr - vAdrs[i] + rAdrs[i];
                            break;
                        }

                    *(uint*)mdDirPtr = 0;
                    *((uint*)mdDirPtr + 1) = 0;
                    *((uint*)mdDirPtr + 2) = 0;
                    *((uint*)mdDirPtr + 3) = 0;


                    byte* mdHdrPtr = bas + mdHdr;
                    VirtualProtect(mdHdrPtr, 4, 0x40, out old);
                    *(uint*)mdHdrPtr = 0;
                    mdHdrPtr += 12;
                    mdHdrPtr += *(uint*)mdHdrPtr;
                    mdHdrPtr = (byte*)(((ulong)mdHdrPtr + 7) & ~3UL);
                    mdHdrPtr += 2;
                    ushort numOfStream = *mdHdrPtr;
                    mdHdrPtr += 2;
                    for (int i = 0; i < numOfStream; i++)
                    {
                        VirtualProtect(mdHdrPtr, 8, 0x40, out old);
                        //*(uint*)mdHdrPtr = 0;
                        mdHdrPtr += 4;
                        //*(uint*)mdHdrPtr = 0;
                        mdHdrPtr += 4;
                        for (int ii = 0; ii < 8; ii++)
                        {
                            VirtualProtect(mdHdrPtr, 4, 0x40, out old);
                            *mdHdrPtr = 0;
                            mdHdrPtr++;
                            if (*mdHdrPtr == 0)
                            {
                                mdHdrPtr += 3;
                                break;
                            }

                            *mdHdrPtr = 0;
                            mdHdrPtr++;
                            if (*mdHdrPtr == 0)
                            {
                                mdHdrPtr += 2;
                                break;
                            }

                            *mdHdrPtr = 0;
                            mdHdrPtr++;
                            if (*mdHdrPtr == 0)
                            {
                                mdHdrPtr += 1;
                                break;
                            }

                            *mdHdrPtr = 0;
                            mdHdrPtr++;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Detecções de Máquinas virtuais
        /// Link do código onde eu peguei algumas funções
        /// https://github.com/KNIF/Guardian/blob/master/Guardian/AntiEmulation.cs
        /// </summary>
        private class SandBoxDetectionsTechniques : NottextProtection
        {
            /// <summary>
            /// Importação da DLL para checkar se estamos em uma máquina virtual
            /// Ou sendo emulado
            /// </summary>
            [DllImport("kernel32.dll")]
            static extern IntPtr GetModuleHandle(
                string lpModuleName // Nome do modulo
            );

            /// <summary>
            /// Saber se está sendo executado em uma máquina virtual
            /// </summary>
            public static void IsRunningOnVirtualBox()
            {
                // Um "procurador" para selecionar os sistema
                var searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem");

                // Procur todos os itens no items
                foreach (var item in searcher.Get())
                {
                    // Manufatura do item
                    string manuFacture = item["Manufacturer"].ToString().ToLower();

                    // Saber se o modelo contém algo com o nome "VIRTUAL"
                    bool modelContains = item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL");

                    // Hora de checkar
                    if (
                        // Saber se contém algo com o nome da Microsoft
                        // E se o modelContains for true
                        manuFacture == "microsoft corporation" &&
                        modelContains ||

                        // Ok, hora de outros checks

                        // Saber se contém o nome de VMWare
                        manuFacture.Contains("vmware") ||

                        // Saber se contém o nome de VMWare
                        manuFacture.Contains("virtualbox") ||

                        // Se o modelo conter o nome do VirtualBox
                        item["Model"].ToString().ToLower() == "virtualbox" ||

                        // Saber se o nome do modelo contém o VMWare
                        item["Model"].ToString().ToLower() == "vmware"
                        )
                    {
                        // Máquina virtual encontrada, vamos sair
                        if (1 * 95 != 55)
                        {
                            // Saia
                            Cracked("O programa não pode ser executado em uma máquina virtual");
                        }
                    }
                }

                // Novo search, pois vamos usar também, o controle do vídeo
                var searcherVideos = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_VideoController");

                // Se as verificações antigas falharem, vamos fazer outras
                foreach (var item in searcherVideos.Get())
                {
                    // Obtem o nome do searcher
                    string name = item.GetPropertyValue("Name").ToString().ToLower();

                    // Agora, hora de fazermos umas verificações
                    if (
                        // Se conter os nomes das máquinas virtuais
                        name.Contains("vmware") ||
                        name.Contains("virtualbox")
                        )
                    {
                        // Outra verificação descartável
                        if (5 * 95 != 2 && true != false)
                        {
                            Cracked("O programa não pode ser executado em uma máquina virtual");
                        }
                        else
                        {
                            // Se os valores forem mudados, saia
                            Cracked("Um valor específico foi modificado");
                        }
                    }
                }
            }

            /// <summary>
            /// Saber se está sendo executado em uma SandBox
            /// </summary>
            public static void IsRunningOnSandBox()
            {
                // Saber se essa DLL está sendo carregada na nossa mémoria
                if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
                {
                    // Verificação inútil
                    if (95 * 2000 != 2)
                    {
                        // Saia
                        Cracked("O aplicativo não pode ser executado em uma SandBox");
                    }
                    else
                    {
                        // Se os valores forem mudados, saia
                        Cracked("Um valor específico foi modificado");
                    }
                }
            }

            /// <summary>
            /// Outra verificação para saber se está sendo executado em uma
            /// Sandbox, com algoritimo de hash
            /// </summary>
            public static void AssemblyHashAlgorithm()
            {
                // Gerar um número aleatorio
                int num = new Random().Next(3000, 10000);

                // Data atual
                DateTime now = DateTime.Now;

                // Durma
                Thread.Sleep(num);

                // Se o tempo de agora, menos o de agora com milisegundo for menor
                // Que o número gerado
                if ((DateTime.Now - now).TotalMilliseconds < (double)num)
                {
                    // Outras verificações
                    if (6 * 4 != 2 && 3 - 2 != 5)
                    {
                        // Aplicativo crackeado
                        Cracked("O altoritimo de hash-assembly não corresponde corretamente");
                    }
                    else
                    {
                        // Se os valores forem mudados, saia
                        Cracked("Um valor específico foi modificado");
                    }
                }
            }

            /// <summary>
            /// Chama todas as funções da parte de detecção de emulação
            /// Ou máquina virtual
            /// </summary>
            public static void VM()
            {
                // Saber se está sendo executado em uma VM
                IsRunningOnVirtualBox();

                // Anti-sandbox
                IsRunningOnSandBox();

                // Pegue os algoritimos dos hashes
                //AssemblyHashAlgorithm();
            }
        }

        /// <summary>
        /// Função para causar BSOD sem poderes administrativos
        /// </summary>
        private class BSOD : NottextProtection
        {
            /// <summary>
            /// Importação da DLL para causar BSOD
            /// </summary>
            [DllImport("ntdll.dll")]
            static extern uint RtlAdjustPrivilege(
                int Privilege, // Privilegio
                bool bEnablePrivilege, // Ativar privilegio
                bool IsThreadPrivilege, // Thread privilegiado
                out bool PreviousValue // Valor
            );

            /// <summary>
            /// Importação da DLL para causar o BSOD
            /// </summary>
            [DllImport("ntdll.dll")]
            static extern uint NtRaiseHardError(
                uint ErrorStatus, // Status do erro
                uint NumberOfParameters, // Parametros
                uint UnicodeStringParameterMask, // Unicode
                IntPtr Parameters, // Outros parametros
                uint ValidResponseOption, // Validar o response
                out uint Response // Response
            );

            /// <summary>
            /// Função que vai causar o BSOD
            /// </summary>
            public static unsafe void CauseBSOD()
            {
                // Um boolean
                Boolean t1;

                // Uint
                uint t2;

                // Vamos ajustar nossos privilegios
                RtlAdjustPrivilege(
                    19, // SE_SHUTDOWN_PRIVILEGE
                    true, // Ativar privilegio
                    false, // Thread privilegiado, não
                    out t1 // Lembra dele? salve aqui
                );

                // Agora, cause o BSOD
                NtRaiseHardError(
                    0xc0000022, // Informações do erro
                    0, // Sem parametros
                    0,
                    IntPtr.Zero,
                    6,
                    out t2 // Vamos usa-ló
                );
            }
        }

        /// <summary>
        /// Vai conter as proteções de lojas, hardware, e DRM
        /// </summary>
        private class DRM : NottextProtection
        {
            /// <summary>
            /// Retorna as configurações do computador, como ID,
            /// Processador, Familia, Serial e etc
            /// </summary>
            private static string ReturnComputerConfigs()
            {
                // Novo RegistryKey, abra uma base de chave
                RegistryKey key = RegistryKey.OpenBaseKey(
                    RegistryHive.LocalMachine, // LocalMachine
                    RegistryView.Registry32 // 32 bits
                );

                // Se o sistema for 64bits
                if (Environment.Is64BitOperatingSystem)
                {
                    // Altere o valor, pra não causa erro
                    key = RegistryKey.OpenBaseKey(
                        RegistryHive.LocalMachine, // LocalMachine
                        RegistryView.Registry64 // 64 bits
                    );
                }

                // Obtenha o valor MachineGuid, no local: Cryptography
                string GUID = key.OpenSubKey(
                    // Local do regedit
                    "SOFTWARE\\Microsoft\\Cryptography"
                ).GetValue(
                    // Valor que queremos
                    "MachineGuid"
                ).ToString();

                // Vamos usar essas strings para obter as configuraç~eos
                string processorSearch = "Select * From Win32_processor";
                string baseSearch = "Select * From Win32_BaseBoard";

                // Vamos chamar a função para procurar todos os dados
                // Que queremos para comparar depois

                // ID do processador
                string processorID = ManagementObjectSearch(processorSearch, "ProcessorId");

                // Familia do processador
                string family = ManagementObjectSearch(processorSearch, "Family");

                // Arquitetura do processador
                string architecture = ManagementObjectSearch(processorSearch, "Architecture");

                // "Cabeçalho" de acordo com o Google
                string caption = ManagementObjectSearch(processorSearch, "Caption");

                // Serial
                string serial = ManagementObjectSearch(baseSearch, "SerialNumber");

                // Nome do aplicativo, pra tornar essa licensa válida somente pra esse
                // Aplicativo
                string applicationName = FileName;

                // Vamos obter todos os valores, e criar um "usuário" com este
                // Hadware
                string hadwareSetting = GUID + processorID + caption + family + architecture + serial + applicationName;

                // Retorne a string, que contém tudo
                return hadwareSetting;
            }

            /// <summary>
            /// Proteção por hadware, usado na loja Nottext
            /// </summary>
            public static void HardwareProtection()
            {
                // Verificação falsa
                if (true != false && 55 * 9 != 20)
                {
                    // Vamos criptografar esse valor para comparar com o arquivo
                    string hadwareEncrypted = Cryptography.Encrypt(
                        // Configurações do hardware, Windows e etc
                        ReturnComputerConfigs(),

                        // Use as configurações de hardware como criptografia.
                        // Assim, só esse hardware poderá descriptografar o arquivo
                        // Corretamente
                        ReturnComputerConfigs()
                    );

                    // Verificação falsa
                    if (true == true)
                    {
                        // Se o arquivo de chave for diferente das configurações do PC
                        // Este usuário não comprou uma licença original 
                        if (File.ReadAllText(keyFile) != hadwareEncrypted)
                        {
                            // Saia do programa
                            Cracked("O hardware específico não corresponde com a chave do aplicativo, tente obter uma nova chave de máquina");
                        }
                    }

                    // Se for modificado
                    else
                    {
                        // Valores alterados, saia
                        Cracked("Um valor específico foi alterado");
                    }
                }

                // Valores modificado
                else
                {
                    // Se os valores forem mudados, saia
                    Cracked("Um valor específico foi modificado");
                }
            }
        }

        /// <summary>
        /// Proteção de tudo, inicializa todas as verificações
        /// Pra executar ele, troque o "InitializeProtection" pra "Main"
        /// </summary>
        [STAThread]
        public void InitializeProtection()
        {
            try
            {
                // PID para a auto-depuração
                int pid = 0;

                // Obtenha os argumentos, que será o número do PID
                string[] arguments = Environment.GetCommandLineArgs();

                // Agora, procure todos os argumentos passados
                foreach (string arg in arguments)
                {
                    // E converta o valor para o PID, que será o processo
                    int.TryParse(arg, out pid);
                }

                // Inicie a proteção com VirtualProtect
                VirtualProtectTechniques.InitializeVirutalProtect();

                // Se o PID for diferente de 0, significa que a gente recebeu
                // Algum PID pra depurar
                if (pid != 0)
                {
                    // Verifique se o PID em que foi passado como parametro
                    // É o memso PID que a gente deseja analisar
                    DebuggerDetectionsTechniques.UserMode.AutoDebugger.CheckPid(pid);

                    // Agora, comece a se auto-depurar, para impedir que o depurador
                    // Anexe o processo á ele, ou que o arquivo seja aberto por
                    // Um depurador
                    DebuggerDetectionsTechniques.UserMode.AutoDebugger.SelfDebugger(pid);

                    // Pare, as verificações já foram feitas pelo processo
                    // Pai, que está nós depurado, então, não faça as verificações
                    // Novamente, porque os métodos anti-debug iriam nós detectar
                    return;
                }

                // Cheque se acabou o mês de pagamento, se ele não tiver
                // Acabado, inicie a proteção
                if (!Expiration())
                {
                    // Vamos verificar se o FOR foi modificado
                    // Porque se o engenheiro reverso modificar o código
                    // Devemos sair, isso vai dificultar mais caso ele
                    // Queira ir passo á passo no código
                    int await = TrickTechniques.AwaitLoop();

                    // Se o "await" for modificado
                    if (await != 1000)
                    {
                        // Valor modificado, saia
                        Cracked("Um valor específico foi modificado");
                    }

                    // Vamos nós ocultar do depurador (user-mode)
                    DebuggerDetectionsTechniques.UserMode.HideOSThreads();

                    // Vefique se o programa não está sendo depurado (user-mode)
                    DebuggerDetectionsTechniques.UserMode.AntiDebugger();

                    // Agora, verifique se o programa não está sendo depurado (kernel-mode)
                    DebuggerDetectionsTechniques.KernelMode.AntiDebugger();

                    // Vamos habiltiar o anti-programas para os depuradores
                    TrickTechniques.AntiPrograms(
                        DebuggersNames, // Lista dos nomes dos depuradores
                        2000 // De 2 em 2 segundos
                    );

                    // Vamos saber se há alguma proxy ativada
                    // Porque se tiver, nosso programa pode ser burlado
                    IsConnectedToProxy();

                    // Vamos obter as configurações de hadware do PC
                    // E vamos verificar se o usuário comprou o software
                    DRM.HardwareProtection();

                    // Agora, verifique se não estamos sendo executados em uma
                    // Máquina virtual ou em uma sandbox
                    SandBoxDetectionsTechniques.VM();

                    // Verifique se o anti-cheat está ativado
                    if (AntiCheat == true)
                    {
                        // Vamos habiltiar o anti-programas para os cheat é outros
                        TrickTechniques.AntiPrograms(
                            CheatersName, // Lista dos nomes dos programas usados para cheat
                            5000 // De 5 em 5 segundos
                        );
                    }

                    // Cheque a última modificação do arquivo
                    ModificationsDetectionsTechniques.LastModifiedFile();

                    // Cheque o tamanho do arquivo
                    ModificationsDetectionsTechniques.MD5Protection();

                    /*
                    // Ok, agora vamos tratar TODOS os erros que ocorrerem no aplicativo
                    AppDomain.CurrentDomain.FirstChanceException += (sender, eventArgs) =>
                    {
                        // Se ocorrer um erro, simplesmente, saia
                        throw new NotImplementedException();
                    };
                    */

                    // Vamos habilitar a proteção de DLL
                    DllProtection();

                    // Se o PID for 0, significa que a gente não recebeu
                    // O valor para depurar, então, vamos depurar o nosso processo
                    if (pid == 0)
                    {
                        // Agora, comece a se auto-depurar, para impedir que o depurador
                        // Anexe o processo á ele, ou que o arquivo seja aberto por
                        // Um depurador
                        DebuggerDetectionsTechniques.UserMode.AutoDebugger.SelfDebugger(pid);
                    }
                }
            }
            catch (Exception)
            {
                // Ocorreu um erro, vamos sair
                Cracked("Ocorreu um erro durante a chamada de inicialização");
            }
        }

    }
}

