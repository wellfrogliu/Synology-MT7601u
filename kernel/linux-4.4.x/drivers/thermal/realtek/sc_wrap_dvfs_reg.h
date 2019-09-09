/**************************************************************
// Spec Version                  : 0.6
// Parser Version                : DVR_Parser_6.11(120105)
// CModelGen Version             : 5.1 2012.01.05
// Naming Rule                   :  Module_Register_Name
// Naming Rule                   : Module_Register_Name_reg
// Parse Option                  : Only Parse _op1
// Parse Address Region          : All Address Region
// Decode bit number             : 12 bits
// Firmware Header Generate Date : 2015/6/28 12:57:20
***************************************************************/

#ifndef _SC_WRAP_DVFS_REG_H_INCLUDED_
#define _SC_WRAP_DVFS_REG_H_INCLUDED_

#define SC_WRAP_DVFS_SC_CRT_CTRL                                                     0x00
#define SC_WRAP_DVFS_SC_CRT_CTRL_reg_addr                                            "0x9801D100"
#define SC_WRAP_DVFS_SC_CRT_CTRL_reg                                                 0x9801D100
#define set_SC_WRAP_DVFS_SC_CRT_CTRL_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_CRT_CTRL_reg)=data)
#define get_SC_WRAP_DVFS_SC_CRT_CTRL_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_CRT_CTRL_reg))
#define SC_WRAP_DVFS_SC_CRT_CTRL_inst_adr                                            "0x0040"
#define SC_WRAP_DVFS_SC_CRT_CTRL_inst                                                0x0040
#define SC_WRAP_DVFS_SC_CRT_CTRL_dy_icg_en_dvfs_shift                                (31)
#define SC_WRAP_DVFS_SC_CRT_CTRL_dy_icg_en_dvfs_mask                                 (0x80000000)
#define SC_WRAP_DVFS_SC_CRT_CTRL_dy_icg_en_dvfs(data)                                (0x80000000&((data)<<31))
#define SC_WRAP_DVFS_SC_CRT_CTRL_dy_icg_en_dvfs_src(data)                            ((0x80000000&(data))>>31)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_dy_icg_en_dvfs(data)                            ((0x80000000&(data))>>31)
#define SC_WRAP_DVFS_SC_CRT_CTRL_AXIM_CLKDIV_shift                                   (28)
#define SC_WRAP_DVFS_SC_CRT_CTRL_AXIM_CLKDIV_mask                                    (0x10000000)
#define SC_WRAP_DVFS_SC_CRT_CTRL_AXIM_CLKDIV(data)                                   (0x10000000&((data)<<28))
#define SC_WRAP_DVFS_SC_CRT_CTRL_AXIM_CLKDIV_src(data)                               ((0x10000000&(data))>>28)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_AXIM_CLKDIV(data)                               ((0x10000000&(data))>>28)
#define SC_WRAP_DVFS_SC_CRT_CTRL_DBGPWRDUP_shift                                     (24)
#define SC_WRAP_DVFS_SC_CRT_CTRL_DBGPWRDUP_mask                                      (0x0F000000)
#define SC_WRAP_DVFS_SC_CRT_CTRL_DBGPWRDUP(data)                                     (0x0F000000&((data)<<24))
#define SC_WRAP_DVFS_SC_CRT_CTRL_DBGPWRDUP_src(data)                                 ((0x0F000000&(data))>>24)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_DBGPWRDUP(data)                                 ((0x0F000000&(data))>>24)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENTRC_shift                                      (20)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENTRC_mask                                       (0x00100000)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENTRC(data)                                      (0x00100000&((data)<<20))
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENTRC_src(data)                                  ((0x00100000&(data))>>20)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_CLKENTRC(data)                                  ((0x00100000&(data))>>20)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENAPB_shift                                      (19)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENAPB_mask                                       (0x00080000)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENAPB(data)                                      (0x00080000&((data)<<19))
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENAPB_src(data)                                  ((0x00080000&(data))>>19)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_CLKENAPB(data)                                  ((0x00080000&(data))>>19)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENATB_shift                                      (18)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENATB_mask                                       (0x00040000)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENATB(data)                                      (0x00040000&((data)<<18))
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENATB_src(data)                                  ((0x00040000&(data))>>18)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_CLKENATB(data)                                  ((0x00040000&(data))>>18)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENAPBCS_shift                                    (17)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENAPBCS_mask                                     (0x00020000)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENAPBCS(data)                                    (0x00020000&((data)<<17))
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENAPBCS_src(data)                                ((0x00020000&(data))>>17)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_CLKENAPBCS(data)                                ((0x00020000&(data))>>17)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENATBCS_shift                                    (16)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENATBCS_mask                                     (0x00010000)
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENATBCS(data)                                    (0x00010000&((data)<<16))
#define SC_WRAP_DVFS_SC_CRT_CTRL_CLKENATBCS_src(data)                                ((0x00010000&(data))>>16)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_CLKENATBCS(data)                                ((0x00010000&(data))>>16)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nPRESETDBG_shift                                    (13)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nPRESETDBG_mask                                     (0x00002000)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nPRESETDBG(data)                                    (0x00002000&((data)<<13))
#define SC_WRAP_DVFS_SC_CRT_CTRL_nPRESETDBG_src(data)                                ((0x00002000&(data))>>13)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_nPRESETDBG(data)                                ((0x00002000&(data))>>13)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nSOCDEBUGRESET_shift                                (12)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nSOCDEBUGRESET_mask                                 (0x00001000)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nSOCDEBUGRESET(data)                                (0x00001000&((data)<<12))
#define SC_WRAP_DVFS_SC_CRT_CTRL_nSOCDEBUGRESET_src(data)                            ((0x00001000&(data))>>12)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_nSOCDEBUGRESET(data)                            ((0x00001000&(data))>>12)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nGICRESET_shift                                     (11)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nGICRESET_mask                                      (0x00000800)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nGICRESET(data)                                     (0x00000800&((data)<<11))
#define SC_WRAP_DVFS_SC_CRT_CTRL_nGICRESET_src(data)                                 ((0x00000800&(data))>>11)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_nGICRESET(data)                                 ((0x00000800&(data))>>11)
#define SC_WRAP_DVFS_SC_CRT_CTRL_L2FLUSHREQ_shift                                    (10)
#define SC_WRAP_DVFS_SC_CRT_CTRL_L2FLUSHREQ_mask                                     (0x00000400)
#define SC_WRAP_DVFS_SC_CRT_CTRL_L2FLUSHREQ(data)                                    (0x00000400&((data)<<10))
#define SC_WRAP_DVFS_SC_CRT_CTRL_L2FLUSHREQ_src(data)                                ((0x00000400&(data))>>10)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_L2FLUSHREQ(data)                                ((0x00000400&(data))>>10)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nL2RESET_shift                                      (9)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nL2RESET_mask                                       (0x00000200)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nL2RESET(data)                                      (0x00000200&((data)<<9))
#define SC_WRAP_DVFS_SC_CRT_CTRL_nL2RESET_src(data)                                  ((0x00000200&(data))>>9)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_nL2RESET(data)                                  ((0x00000200&(data))>>9)
#define SC_WRAP_DVFS_SC_CRT_CTRL_L2RSTDISABLE_shift                                  (8)
#define SC_WRAP_DVFS_SC_CRT_CTRL_L2RSTDISABLE_mask                                   (0x00000100)
#define SC_WRAP_DVFS_SC_CRT_CTRL_L2RSTDISABLE(data)                                  (0x00000100&((data)<<8))
#define SC_WRAP_DVFS_SC_CRT_CTRL_L2RSTDISABLE_src(data)                              ((0x00000100&(data))>>8)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_L2RSTDISABLE(data)                              ((0x00000100&(data))>>8)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nCORERESET_shift                                    (4)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nCORERESET_mask                                     (0x000000F0)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nCORERESET(data)                                    (0x000000F0&((data)<<4))
#define SC_WRAP_DVFS_SC_CRT_CTRL_nCORERESET_src(data)                                ((0x000000F0&(data))>>4)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_nCORERESET(data)                                ((0x000000F0&(data))>>4)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nCOREPORESET_shift                                  (0)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nCOREPORESET_mask                                   (0x0000000F)
#define SC_WRAP_DVFS_SC_CRT_CTRL_nCOREPORESET(data)                                  (0x0000000F&((data)<<0))
#define SC_WRAP_DVFS_SC_CRT_CTRL_nCOREPORESET_src(data)                              ((0x0000000F&(data))>>0)
#define SC_WRAP_DVFS_SC_CRT_CTRL_get_nCOREPORESET(data)                              ((0x0000000F&(data))>>0)

#define SC_WRAP_DVFS_SC_STAT                                                         0x04
#define SC_WRAP_DVFS_SC_STAT_reg_addr                                                "0x9801D104"
#define SC_WRAP_DVFS_SC_STAT_reg                                                     0x9801D104
#define set_SC_WRAP_DVFS_SC_STAT_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_STAT_reg)=data)
#define get_SC_WRAP_DVFS_SC_STAT_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_STAT_reg))
#define SC_WRAP_DVFS_SC_STAT_inst_adr                                                "0x0041"
#define SC_WRAP_DVFS_SC_STAT_inst                                                    0x0041
#define SC_WRAP_DVFS_SC_STAT_WARMRSTREQ_shift                                        (20)
#define SC_WRAP_DVFS_SC_STAT_WARMRSTREQ_mask                                         (0x00F00000)
#define SC_WRAP_DVFS_SC_STAT_WARMRSTREQ(data)                                        (0x00F00000&((data)<<20))
#define SC_WRAP_DVFS_SC_STAT_WARMRSTREQ_src(data)                                    ((0x00F00000&(data))>>20)
#define SC_WRAP_DVFS_SC_STAT_get_WARMRSTREQ(data)                                    ((0x00F00000&(data))>>20)
#define SC_WRAP_DVFS_SC_STAT_SMPEN_shift                                             (16)
#define SC_WRAP_DVFS_SC_STAT_SMPEN_mask                                              (0x000F0000)
#define SC_WRAP_DVFS_SC_STAT_SMPEN(data)                                             (0x000F0000&((data)<<16))
#define SC_WRAP_DVFS_SC_STAT_SMPEN_src(data)                                         ((0x000F0000&(data))>>16)
#define SC_WRAP_DVFS_SC_STAT_get_SMPEN(data)                                         ((0x000F0000&(data))>>16)
#define SC_WRAP_DVFS_SC_STAT_L2FLUSHDONE_shift                                       (10)
#define SC_WRAP_DVFS_SC_STAT_L2FLUSHDONE_mask                                        (0x00000400)
#define SC_WRAP_DVFS_SC_STAT_L2FLUSHDONE(data)                                       (0x00000400&((data)<<10))
#define SC_WRAP_DVFS_SC_STAT_L2FLUSHDONE_src(data)                                   ((0x00000400&(data))>>10)
#define SC_WRAP_DVFS_SC_STAT_get_L2FLUSHDONE(data)                                   ((0x00000400&(data))>>10)
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFIL2_shift                                      (8)
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFIL2_mask                                       (0x00000100)
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFIL2(data)                                      (0x00000100&((data)<<8))
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFIL2_src(data)                                  ((0x00000100&(data))>>8)
#define SC_WRAP_DVFS_SC_STAT_get_STANDBYWFIL2(data)                                  ((0x00000100&(data))>>8)
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFE_shift                                        (4)
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFE_mask                                         (0x000000F0)
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFE(data)                                        (0x000000F0&((data)<<4))
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFE_src(data)                                    ((0x000000F0&(data))>>4)
#define SC_WRAP_DVFS_SC_STAT_get_STANDBYWFE(data)                                    ((0x000000F0&(data))>>4)
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFI_shift                                        (0)
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFI_mask                                         (0x0000000F)
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFI(data)                                        (0x0000000F&((data)<<0))
#define SC_WRAP_DVFS_SC_STAT_STANDBYWFI_src(data)                                    ((0x0000000F&(data))>>0)
#define SC_WRAP_DVFS_SC_STAT_get_STANDBYWFI(data)                                    ((0x0000000F&(data))>>0)

#define SC_WRAP_DVFS_SC_INT_STAT                                                     0x08
#define SC_WRAP_DVFS_SC_INT_STAT_reg_addr                                            "0x9801D108"
#define SC_WRAP_DVFS_SC_INT_STAT_reg                                                 0x9801D108
#define set_SC_WRAP_DVFS_SC_INT_STAT_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_INT_STAT_reg)=data)
#define get_SC_WRAP_DVFS_SC_INT_STAT_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_INT_STAT_reg))
#define SC_WRAP_DVFS_SC_INT_STAT_inst_adr                                            "0x0042"
#define SC_WRAP_DVFS_SC_INT_STAT_inst                                                0x0042
#define SC_WRAP_DVFS_SC_INT_STAT_nFRQOUT_shift                                       (12)
#define SC_WRAP_DVFS_SC_INT_STAT_nFRQOUT_mask                                        (0x0000F000)
#define SC_WRAP_DVFS_SC_INT_STAT_nFRQOUT(data)                                       (0x0000F000&((data)<<12))
#define SC_WRAP_DVFS_SC_INT_STAT_nFRQOUT_src(data)                                   ((0x0000F000&(data))>>12)
#define SC_WRAP_DVFS_SC_INT_STAT_get_nFRQOUT(data)                                   ((0x0000F000&(data))>>12)
#define SC_WRAP_DVFS_SC_INT_STAT_nIRQOUT_shift                                       (8)
#define SC_WRAP_DVFS_SC_INT_STAT_nIRQOUT_mask                                        (0x00000F00)
#define SC_WRAP_DVFS_SC_INT_STAT_nIRQOUT(data)                                       (0x00000F00&((data)<<8))
#define SC_WRAP_DVFS_SC_INT_STAT_nIRQOUT_src(data)                                   ((0x00000F00&(data))>>8)
#define SC_WRAP_DVFS_SC_INT_STAT_get_nIRQOUT(data)                                   ((0x00000F00&(data))>>8)
#define SC_WRAP_DVFS_SC_INT_STAT_nEXTERRIRQ_shift                                    (4)
#define SC_WRAP_DVFS_SC_INT_STAT_nEXTERRIRQ_mask                                     (0x00000010)
#define SC_WRAP_DVFS_SC_INT_STAT_nEXTERRIRQ(data)                                    (0x00000010&((data)<<4))
#define SC_WRAP_DVFS_SC_INT_STAT_nEXTERRIRQ_src(data)                                ((0x00000010&(data))>>4)
#define SC_WRAP_DVFS_SC_INT_STAT_get_nEXTERRIRQ(data)                                ((0x00000010&(data))>>4)
#define SC_WRAP_DVFS_SC_INT_STAT_nPMUIRQ_shift                                       (0)
#define SC_WRAP_DVFS_SC_INT_STAT_nPMUIRQ_mask                                        (0x0000000F)
#define SC_WRAP_DVFS_SC_INT_STAT_nPMUIRQ(data)                                       (0x0000000F&((data)<<0))
#define SC_WRAP_DVFS_SC_INT_STAT_nPMUIRQ_src(data)                                   ((0x0000000F&(data))>>0)
#define SC_WRAP_DVFS_SC_INT_STAT_get_nPMUIRQ(data)                                   ((0x0000000F&(data))>>0)

#define SC_WRAP_DVFS_SC_SEC_CTRL                                                     0x0C
#define SC_WRAP_DVFS_SC_SEC_CTRL_reg_addr                                            "0x9801D10C"
#define SC_WRAP_DVFS_SC_SEC_CTRL_reg                                                 0x9801D10C
#define set_SC_WRAP_DVFS_SC_SEC_CTRL_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_SEC_CTRL_reg)=data)
#define get_SC_WRAP_DVFS_SC_SEC_CTRL_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_SEC_CTRL_reg))
#define SC_WRAP_DVFS_SC_SEC_CTRL_inst_adr                                            "0x0043"
#define SC_WRAP_DVFS_SC_SEC_CTRL_inst                                                0x0043
#define SC_WRAP_DVFS_SC_SEC_CTRL_cfgsdisable_i_shift                                 (4)
#define SC_WRAP_DVFS_SC_SEC_CTRL_cfgsdisable_i_mask                                  (0x00000010)
#define SC_WRAP_DVFS_SC_SEC_CTRL_cfgsdisable_i(data)                                 (0x00000010&((data)<<4))
#define SC_WRAP_DVFS_SC_SEC_CTRL_cfgsdisable_i_src(data)                             ((0x00000010&(data))>>4)
#define SC_WRAP_DVFS_SC_SEC_CTRL_get_cfgsdisable_i(data)                             ((0x00000010&(data))>>4)
#define SC_WRAP_DVFS_SC_SEC_CTRL_cp15disable_i_shift                                 (0)
#define SC_WRAP_DVFS_SC_SEC_CTRL_cp15disable_i_mask                                  (0x0000000F)
#define SC_WRAP_DVFS_SC_SEC_CTRL_cp15disable_i(data)                                 (0x0000000F&((data)<<0))
#define SC_WRAP_DVFS_SC_SEC_CTRL_cp15disable_i_src(data)                             ((0x0000000F&(data))>>0)
#define SC_WRAP_DVFS_SC_SEC_CTRL_get_cp15disable_i(data)                             ((0x0000000F&(data))>>0)

#define SC_WRAP_DVFS_SC_PMUEVENT0                                                    0x10
#define SC_WRAP_DVFS_SC_PMUEVENT0_reg_addr                                           "0x9801D110"
#define SC_WRAP_DVFS_SC_PMUEVENT0_reg                                                0x9801D110
#define set_SC_WRAP_DVFS_SC_PMUEVENT0_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_PMUEVENT0_reg)=data)
#define get_SC_WRAP_DVFS_SC_PMUEVENT0_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_PMUEVENT0_reg))
#define SC_WRAP_DVFS_SC_PMUEVENT0_inst_adr                                           "0x0044"
#define SC_WRAP_DVFS_SC_PMUEVENT0_inst                                               0x0044
#define SC_WRAP_DVFS_SC_PMUEVENT0_PMUEVENT0_shift                                    (0)
#define SC_WRAP_DVFS_SC_PMUEVENT0_PMUEVENT0_mask                                     (0x3FFFFFFF)
#define SC_WRAP_DVFS_SC_PMUEVENT0_PMUEVENT0(data)                                    (0x3FFFFFFF&((data)<<0))
#define SC_WRAP_DVFS_SC_PMUEVENT0_PMUEVENT0_src(data)                                ((0x3FFFFFFF&(data))>>0)
#define SC_WRAP_DVFS_SC_PMUEVENT0_get_PMUEVENT0(data)                                ((0x3FFFFFFF&(data))>>0)

#define SC_WRAP_DVFS_SC_PMUEVENT1                                                    0x14
#define SC_WRAP_DVFS_SC_PMUEVENT1_reg_addr                                           "0x9801D114"
#define SC_WRAP_DVFS_SC_PMUEVENT1_reg                                                0x9801D114
#define set_SC_WRAP_DVFS_SC_PMUEVENT1_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_PMUEVENT1_reg)=data)
#define get_SC_WRAP_DVFS_SC_PMUEVENT1_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_PMUEVENT1_reg))
#define SC_WRAP_DVFS_SC_PMUEVENT1_inst_adr                                           "0x0045"
#define SC_WRAP_DVFS_SC_PMUEVENT1_inst                                               0x0045
#define SC_WRAP_DVFS_SC_PMUEVENT1_PMUEVENT1_shift                                    (0)
#define SC_WRAP_DVFS_SC_PMUEVENT1_PMUEVENT1_mask                                     (0x3FFFFFFF)
#define SC_WRAP_DVFS_SC_PMUEVENT1_PMUEVENT1(data)                                    (0x3FFFFFFF&((data)<<0))
#define SC_WRAP_DVFS_SC_PMUEVENT1_PMUEVENT1_src(data)                                ((0x3FFFFFFF&(data))>>0)
#define SC_WRAP_DVFS_SC_PMUEVENT1_get_PMUEVENT1(data)                                ((0x3FFFFFFF&(data))>>0)

#define SC_WRAP_DVFS_SC_PMUEVENT2                                                    0x18
#define SC_WRAP_DVFS_SC_PMUEVENT2_reg_addr                                           "0x9801D118"
#define SC_WRAP_DVFS_SC_PMUEVENT2_reg                                                0x9801D118
#define set_SC_WRAP_DVFS_SC_PMUEVENT2_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_PMUEVENT2_reg)=data)
#define get_SC_WRAP_DVFS_SC_PMUEVENT2_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_PMUEVENT2_reg))
#define SC_WRAP_DVFS_SC_PMUEVENT2_inst_adr                                           "0x0046"
#define SC_WRAP_DVFS_SC_PMUEVENT2_inst                                               0x0046
#define SC_WRAP_DVFS_SC_PMUEVENT2_PMUEVENT2_shift                                    (0)
#define SC_WRAP_DVFS_SC_PMUEVENT2_PMUEVENT2_mask                                     (0x3FFFFFFF)
#define SC_WRAP_DVFS_SC_PMUEVENT2_PMUEVENT2(data)                                    (0x3FFFFFFF&((data)<<0))
#define SC_WRAP_DVFS_SC_PMUEVENT2_PMUEVENT2_src(data)                                ((0x3FFFFFFF&(data))>>0)
#define SC_WRAP_DVFS_SC_PMUEVENT2_get_PMUEVENT2(data)                                ((0x3FFFFFFF&(data))>>0)

#define SC_WRAP_DVFS_SC_PMUEVENT3                                                    0x1C
#define SC_WRAP_DVFS_SC_PMUEVENT3_reg_addr                                           "0x9801D11C"
#define SC_WRAP_DVFS_SC_PMUEVENT3_reg                                                0x9801D11C
#define set_SC_WRAP_DVFS_SC_PMUEVENT3_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_PMUEVENT3_reg)=data)
#define get_SC_WRAP_DVFS_SC_PMUEVENT3_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_PMUEVENT3_reg))
#define SC_WRAP_DVFS_SC_PMUEVENT3_inst_adr                                           "0x0047"
#define SC_WRAP_DVFS_SC_PMUEVENT3_inst                                               0x0047
#define SC_WRAP_DVFS_SC_PMUEVENT3_PMUEVENT3_shift                                    (0)
#define SC_WRAP_DVFS_SC_PMUEVENT3_PMUEVENT3_mask                                     (0x3FFFFFFF)
#define SC_WRAP_DVFS_SC_PMUEVENT3_PMUEVENT3(data)                                    (0x3FFFFFFF&((data)<<0))
#define SC_WRAP_DVFS_SC_PMUEVENT3_PMUEVENT3_src(data)                                ((0x3FFFFFFF&(data))>>0)
#define SC_WRAP_DVFS_SC_PMUEVENT3_get_PMUEVENT3(data)                                ((0x3FFFFFFF&(data))>>0)

#define SC_WRAP_DVFS_SC_INT_CTRL                                                     0x20
#define SC_WRAP_DVFS_SC_INT_CTRL_reg_addr                                            "0x9801D120"
#define SC_WRAP_DVFS_SC_INT_CTRL_reg                                                 0x9801D120
#define set_SC_WRAP_DVFS_SC_INT_CTRL_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_INT_CTRL_reg)=data)
#define get_SC_WRAP_DVFS_SC_INT_CTRL_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_INT_CTRL_reg))
#define SC_WRAP_DVFS_SC_INT_CTRL_inst_adr                                            "0x0048"
#define SC_WRAP_DVFS_SC_INT_CTRL_inst                                                0x0048
#define SC_WRAP_DVFS_SC_INT_CTRL_PMIRQ_EN_shift                                      (12)
#define SC_WRAP_DVFS_SC_INT_CTRL_PMIRQ_EN_mask                                       (0x0000F000)
#define SC_WRAP_DVFS_SC_INT_CTRL_PMIRQ_EN(data)                                      (0x0000F000&((data)<<12))
#define SC_WRAP_DVFS_SC_INT_CTRL_PMIRQ_EN_src(data)                                  ((0x0000F000&(data))>>12)
#define SC_WRAP_DVFS_SC_INT_CTRL_get_PMIRQ_EN(data)                                  ((0x0000F000&(data))>>12)
#define SC_WRAP_DVFS_SC_INT_CTRL_IRQOUT_EN_shift                                     (8)
#define SC_WRAP_DVFS_SC_INT_CTRL_IRQOUT_EN_mask                                      (0x00000F00)
#define SC_WRAP_DVFS_SC_INT_CTRL_IRQOUT_EN(data)                                     (0x00000F00&((data)<<8))
#define SC_WRAP_DVFS_SC_INT_CTRL_IRQOUT_EN_src(data)                                 ((0x00000F00&(data))>>8)
#define SC_WRAP_DVFS_SC_INT_CTRL_get_IRQOUT_EN(data)                                 ((0x00000F00&(data))>>8)
#define SC_WRAP_DVFS_SC_INT_CTRL_EXTERRIRQ_EN_shift                                  (4)
#define SC_WRAP_DVFS_SC_INT_CTRL_EXTERRIRQ_EN_mask                                   (0x00000010)
#define SC_WRAP_DVFS_SC_INT_CTRL_EXTERRIRQ_EN(data)                                  (0x00000010&((data)<<4))
#define SC_WRAP_DVFS_SC_INT_CTRL_EXTERRIRQ_EN_src(data)                              ((0x00000010&(data))>>4)
#define SC_WRAP_DVFS_SC_INT_CTRL_get_EXTERRIRQ_EN(data)                              ((0x00000010&(data))>>4)
#define SC_WRAP_DVFS_SC_INT_CTRL_PMUIRQ_EN_shift                                     (0)
#define SC_WRAP_DVFS_SC_INT_CTRL_PMUIRQ_EN_mask                                      (0x0000000F)
#define SC_WRAP_DVFS_SC_INT_CTRL_PMUIRQ_EN(data)                                     (0x0000000F&((data)<<0))
#define SC_WRAP_DVFS_SC_INT_CTRL_PMUIRQ_EN_src(data)                                 ((0x0000000F&(data))>>0)
#define SC_WRAP_DVFS_SC_INT_CTRL_get_PMUIRQ_EN(data)                                 ((0x0000000F&(data))>>0)

#define SC_WRAP_DVFS_SC_DSS_0_CTRL                                                   0x28
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_reg_addr                                          "0x9801D128"
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_reg                                               0x9801D128
#define set_SC_WRAP_DVFS_SC_DSS_0_CTRL_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_0_CTRL_reg)=data)
#define get_SC_WRAP_DVFS_SC_DSS_0_CTRL_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_0_CTRL_reg))
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_inst_adr                                          "0x004A"
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_inst                                              0x004A
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_speed_en_shift                                    (16)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_speed_en_mask                                     (0x00FF0000)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_speed_en(data)                                    (0x00FF0000&((data)<<16))
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_speed_en_src(data)                                ((0x00FF0000&(data))>>16)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_get_speed_en(data)                                ((0x00FF0000&(data))>>16)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_wire_sel_shift                                    (4)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_wire_sel_mask                                     (0x00000010)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_wire_sel(data)                                    (0x00000010&((data)<<4))
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_wire_sel_src(data)                                ((0x00000010&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_get_wire_sel(data)                                ((0x00000010&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_ro_sel_shift                                      (1)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_ro_sel_mask                                       (0x0000000E)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_ro_sel(data)                                      (0x0000000E&((data)<<1))
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_ro_sel_src(data)                                  ((0x0000000E&(data))>>1)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_get_ro_sel(data)                                  ((0x0000000E&(data))>>1)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_dss_rst_n_shift                                   (0)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_dss_rst_n_mask                                    (0x00000001)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_dss_rst_n(data)                                   (0x00000001&((data)<<0))
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_dss_rst_n_src(data)                               ((0x00000001&(data))>>0)
#define SC_WRAP_DVFS_SC_DSS_0_CTRL_get_dss_rst_n(data)                               ((0x00000001&(data))>>0)

#define SC_WRAP_DVFS_SC_DSS_0_STATUS                                                 0x30
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_reg_addr                                        "0x9801D130"
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_reg                                             0x9801D130
#define set_SC_WRAP_DVFS_SC_DSS_0_STATUS_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_0_STATUS_reg)=data)
#define get_SC_WRAP_DVFS_SC_DSS_0_STATUS_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_0_STATUS_reg))
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_inst_adr                                        "0x004C"
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_inst                                            0x004C
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_count_out_shift                                 (4)
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_count_out_mask                                  (0x00FFFFF0)
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_count_out(data)                                 (0x00FFFFF0&((data)<<4))
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_count_out_src(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_get_count_out(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_ready_shift                                     (0)
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_ready_mask                                      (0x00000001)
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_ready(data)                                     (0x00000001&((data)<<0))
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_ready_src(data)                                 ((0x00000001&(data))>>0)
#define SC_WRAP_DVFS_SC_DSS_0_STATUS_get_ready(data)                                 ((0x00000001&(data))>>0)

#define SC_WRAP_DVFS_SC_DSS_1_STATUS                                                 0x34
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_reg_addr                                        "0x9801D134"
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_reg                                             0x9801D134
#define set_SC_WRAP_DVFS_SC_DSS_1_STATUS_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_1_STATUS_reg)=data)
#define get_SC_WRAP_DVFS_SC_DSS_1_STATUS_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_1_STATUS_reg))
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_inst_adr                                        "0x004D"
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_inst                                            0x004D
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_count_out_shift                                 (4)
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_count_out_mask                                  (0x00FFFFF0)
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_count_out(data)                                 (0x00FFFFF0&((data)<<4))
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_count_out_src(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_get_count_out(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_ready_shift                                     (0)
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_ready_mask                                      (0x00000001)
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_ready(data)                                     (0x00000001&((data)<<0))
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_ready_src(data)                                 ((0x00000001&(data))>>0)
#define SC_WRAP_DVFS_SC_DSS_1_STATUS_get_ready(data)                                 ((0x00000001&(data))>>0)

#define SC_WRAP_DVFS_SC_DSS_2_STATUS                                                 0x38
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_reg_addr                                        "0x9801D138"
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_reg                                             0x9801D138
#define set_SC_WRAP_DVFS_SC_DSS_2_STATUS_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_2_STATUS_reg)=data)
#define get_SC_WRAP_DVFS_SC_DSS_2_STATUS_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_2_STATUS_reg))
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_inst_adr                                        "0x004E"
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_inst                                            0x004E
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_count_out_shift                                 (4)
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_count_out_mask                                  (0x00FFFFF0)
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_count_out(data)                                 (0x00FFFFF0&((data)<<4))
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_count_out_src(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_get_count_out(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_ready_shift                                     (0)
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_ready_mask                                      (0x00000001)
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_ready(data)                                     (0x00000001&((data)<<0))
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_ready_src(data)                                 ((0x00000001&(data))>>0)
#define SC_WRAP_DVFS_SC_DSS_2_STATUS_get_ready(data)                                 ((0x00000001&(data))>>0)

#define SC_WRAP_DVFS_SC_DSS_3_STATUS                                                 0x3C
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_reg_addr                                        "0x9801D13C"
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_reg                                             0x9801D13C
#define set_SC_WRAP_DVFS_SC_DSS_3_STATUS_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_3_STATUS_reg)=data)
#define get_SC_WRAP_DVFS_SC_DSS_3_STATUS_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_3_STATUS_reg))
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_inst_adr                                        "0x004F"
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_inst                                            0x004F
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_count_out_shift                                 (4)
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_count_out_mask                                  (0x00FFFFF0)
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_count_out(data)                                 (0x00FFFFF0&((data)<<4))
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_count_out_src(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_get_count_out(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_ready_shift                                     (0)
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_ready_mask                                      (0x00000001)
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_ready(data)                                     (0x00000001&((data)<<0))
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_ready_src(data)                                 ((0x00000001&(data))>>0)
#define SC_WRAP_DVFS_SC_DSS_3_STATUS_get_ready(data)                                 ((0x00000001&(data))>>0)

#define SC_WRAP_DVFS_SC_DSS_4_STATUS                                                 0x40
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_reg_addr                                        "0x9801D140"
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_reg                                             0x9801D140
#define set_SC_WRAP_DVFS_SC_DSS_4_STATUS_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_4_STATUS_reg)=data)
#define get_SC_WRAP_DVFS_SC_DSS_4_STATUS_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_4_STATUS_reg))
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_inst_adr                                        "0x0050"
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_inst                                            0x0050
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_count_out_shift                                 (4)
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_count_out_mask                                  (0x00FFFFF0)
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_count_out(data)                                 (0x00FFFFF0&((data)<<4))
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_count_out_src(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_get_count_out(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_ready_shift                                     (0)
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_ready_mask                                      (0x00000001)
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_ready(data)                                     (0x00000001&((data)<<0))
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_ready_src(data)                                 ((0x00000001&(data))>>0)
#define SC_WRAP_DVFS_SC_DSS_4_STATUS_get_ready(data)                                 ((0x00000001&(data))>>0)

#define SC_WRAP_DVFS_SC_DSS_5_STATUS                                                 0x44
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_reg_addr                                        "0x9801D144"
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_reg                                             0x9801D144
#define set_SC_WRAP_DVFS_SC_DSS_5_STATUS_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_5_STATUS_reg)=data)
#define get_SC_WRAP_DVFS_SC_DSS_5_STATUS_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_5_STATUS_reg))
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_inst_adr                                        "0x0051"
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_inst                                            0x0051
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_count_out_shift                                 (4)
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_count_out_mask                                  (0x00FFFFF0)
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_count_out(data)                                 (0x00FFFFF0&((data)<<4))
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_count_out_src(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_get_count_out(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_ready_shift                                     (0)
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_ready_mask                                      (0x00000001)
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_ready(data)                                     (0x00000001&((data)<<0))
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_ready_src(data)                                 ((0x00000001&(data))>>0)
#define SC_WRAP_DVFS_SC_DSS_5_STATUS_get_ready(data)                                 ((0x00000001&(data))>>0)

#define SC_WRAP_DVFS_SC_DSS_6_STATUS                                                 0x48
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_reg_addr                                        "0x9801D148"
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_reg                                             0x9801D148
#define set_SC_WRAP_DVFS_SC_DSS_6_STATUS_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_6_STATUS_reg)=data)
#define get_SC_WRAP_DVFS_SC_DSS_6_STATUS_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_6_STATUS_reg))
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_inst_adr                                        "0x0052"
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_inst                                            0x0052
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_count_out_shift                                 (4)
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_count_out_mask                                  (0x00FFFFF0)
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_count_out(data)                                 (0x00FFFFF0&((data)<<4))
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_count_out_src(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_get_count_out(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_ready_shift                                     (0)
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_ready_mask                                      (0x00000001)
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_ready(data)                                     (0x00000001&((data)<<0))
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_ready_src(data)                                 ((0x00000001&(data))>>0)
#define SC_WRAP_DVFS_SC_DSS_6_STATUS_get_ready(data)                                 ((0x00000001&(data))>>0)

#define SC_WRAP_DVFS_SC_DSS_7_STATUS                                                 0x4C
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_reg_addr                                        "0x9801D14C"
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_reg                                             0x9801D14C
#define set_SC_WRAP_DVFS_SC_DSS_7_STATUS_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_7_STATUS_reg)=data)
#define get_SC_WRAP_DVFS_SC_DSS_7_STATUS_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_SC_DSS_7_STATUS_reg))
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_inst_adr                                        "0x0053"
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_inst                                            0x0053
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_count_out_shift                                 (4)
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_count_out_mask                                  (0x00FFFFF0)
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_count_out(data)                                 (0x00FFFFF0&((data)<<4))
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_count_out_src(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_get_count_out(data)                             ((0x00FFFFF0&(data))>>4)
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_ready_shift                                     (0)
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_ready_mask                                      (0x00000001)
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_ready(data)                                     (0x00000001&((data)<<0))
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_ready_src(data)                                 ((0x00000001&(data))>>0)
#define SC_WRAP_DVFS_SC_DSS_7_STATUS_get_ready(data)                                 ((0x00000001&(data))>>0)

#define SC_WRAP_DVFS_TM_SENSOR_CTRL0                                                 0x50
#define SC_WRAP_DVFS_TM_SENSOR_CTRL0_reg_addr                                        "0x9801D150"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL0_reg                                             0x9801D150
#define set_SC_WRAP_DVFS_TM_SENSOR_CTRL0_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL0_reg)=data)
#define get_SC_WRAP_DVFS_TM_SENSOR_CTRL0_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL0_reg))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL0_inst_adr                                        "0x0054"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL0_inst                                            0x0054
#define SC_WRAP_DVFS_TM_SENSOR_CTRL0_reg_a_shift                                     (0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL0_reg_a_mask                                      (0x1FFFFFFF)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL0_reg_a(data)                                     (0x1FFFFFFF&((data)<<0))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL0_reg_a_src(data)                                 ((0x1FFFFFFF&(data))>>0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL0_get_reg_a(data)                                 ((0x1FFFFFFF&(data))>>0)

#define SC_WRAP_DVFS_TM_SENSOR_CTRL1                                                 0x54
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_addr                                        "0x9801D154"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg                                             0x9801D154
#define set_SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg)=data)
#define get_SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_inst_adr                                        "0x0055"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_inst                                            0x0055
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_chopen_shift                                (28)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_chopen_mask                                 (0x10000000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_chopen(data)                                (0x10000000&((data)<<28))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_chopen_src(data)                            ((0x10000000&(data))>>28)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_get_reg_chopen(data)                            ((0x10000000&(data))>>28)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_cal_en_shift                                (27)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_cal_en_mask                                 (0x08000000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_cal_en(data)                                (0x08000000&((data)<<27))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_cal_en_src(data)                            ((0x08000000&(data))>>27)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_get_reg_cal_en(data)                            ((0x08000000&(data))>>27)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_biasdem_sel_shift                           (26)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_biasdem_sel_mask                            (0x04000000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_biasdem_sel(data)                           (0x04000000&((data)<<26))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_biasdem_sel_src(data)                       ((0x04000000&(data))>>26)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_get_reg_biasdem_sel(data)                       ((0x04000000&(data))>>26)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_biaschop_shift                              (25)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_biaschop_mask                               (0x02000000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_biaschop(data)                              (0x02000000&((data)<<25))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_biaschop_src(data)                          ((0x02000000&(data))>>25)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_get_reg_biaschop(data)                          ((0x02000000&(data))>>25)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_adccksel_shift                              (22)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_adccksel_mask                               (0x01C00000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_adccksel(data)                              (0x01C00000&((data)<<22))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_adccksel_src(data)                          ((0x01C00000&(data))>>22)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_get_reg_adccksel(data)                          ((0x01C00000&(data))>>22)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_b_shift                                     (0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_b_mask                                      (0x003FFFFF)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_b(data)                                     (0x003FFFFF&((data)<<0))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_reg_b_src(data)                                 ((0x003FFFFF&(data))>>0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL1_get_reg_b(data)                                 ((0x003FFFFF&(data))>>0)

#define SC_WRAP_DVFS_TM_SENSOR_CTRL2                                                 0x58
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_addr                                        "0x9801D158"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg                                             0x9801D158
#define set_SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg)=data)
#define get_SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_inst_adr                                        "0x0056"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_inst                                            0x0056
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_vbe_biassel_shift                           (23)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_vbe_biassel_mask                            (0x01800000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_vbe_biassel(data)                           (0x01800000&((data)<<23))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_vbe_biassel_src(data)                       ((0x01800000&(data))>>23)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_vbe_biassel(data)                       ((0x01800000&(data))>>23)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_sdm_test_en_shift                           (22)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_sdm_test_en_mask                            (0x00400000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_sdm_test_en(data)                           (0x00400000&((data)<<22))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_sdm_test_en_src(data)                       ((0x00400000&(data))>>22)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_sdm_test_en(data)                       ((0x00400000&(data))>>22)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_sdm_test_shift                              (21)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_sdm_test_mask                               (0x00200000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_sdm_test(data)                              (0x00200000&((data)<<21))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_sdm_test_src(data)                          ((0x00200000&(data))>>21)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_sdm_test(data)                          ((0x00200000&(data))>>21)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_rstb_shift                                  (20)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_rstb_mask                                   (0x00100000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_rstb(data)                                  (0x00100000&((data)<<20))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_rstb_src(data)                              ((0x00100000&(data))>>20)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_rstb(data)                              ((0x00100000&(data))>>20)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_resol_shift                                 (18)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_resol_mask                                  (0x000C0000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_resol(data)                                 (0x000C0000&((data)<<18))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_resol_src(data)                             ((0x000C0000&(data))>>18)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_resol(data)                             ((0x000C0000&(data))>>18)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_ppow_shift                                  (17)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_ppow_mask                                   (0x00020000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_ppow(data)                                  (0x00020000&((data)<<17))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_ppow_src(data)                              ((0x00020000&(data))>>17)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_ppow(data)                              ((0x00020000&(data))>>17)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_osccursel_shift                             (15)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_osccursel_mask                              (0x00018000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_osccursel(data)                             (0x00018000&((data)<<15))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_osccursel_src(data)                         ((0x00018000&(data))>>15)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_osccursel(data)                         ((0x00018000&(data))>>15)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_order3_shift                                (14)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_order3_mask                                 (0x00004000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_order3(data)                                (0x00004000&((data)<<14))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_order3_src(data)                            ((0x00004000&(data))>>14)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_order3(data)                            ((0x00004000&(data))>>14)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_opcursel_shift                              (12)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_opcursel_mask                               (0x00003000)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_opcursel(data)                              (0x00003000&((data)<<12))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_opcursel_src(data)                          ((0x00003000&(data))>>12)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_opcursel(data)                          ((0x00003000&(data))>>12)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_hold_en_shift                               (11)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_hold_en_mask                                (0x00000800)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_hold_en(data)                               (0x00000800&((data)<<11))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_hold_en_src(data)                           ((0x00000800&(data))>>11)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_hold_en(data)                           ((0x00000800&(data))>>11)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_hold_dly_shift                              (9)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_hold_dly_mask                               (0x00000600)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_hold_dly(data)                              (0x00000600&((data)<<9))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_hold_dly_src(data)                          ((0x00000600&(data))>>9)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_hold_dly(data)                          ((0x00000600&(data))>>9)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_filteredgesel_shift                         (8)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_filteredgesel_mask                          (0x00000100)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_filteredgesel(data)                         (0x00000100&((data)<<8))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_filteredgesel_src(data)                     ((0x00000100&(data))>>8)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_filteredgesel(data)                     ((0x00000100&(data))>>8)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_dsr_shift                                   (5)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_dsr_mask                                    (0x000000E0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_dsr(data)                                   (0x000000E0&((data)<<5))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_dsr_src(data)                               ((0x000000E0&(data))>>5)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_dsr(data)                               ((0x000000E0&(data))>>5)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_cksourcesel_shift                           (4)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_cksourcesel_mask                            (0x00000010)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_cksourcesel(data)                           (0x00000010&((data)<<4))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_cksourcesel_src(data)                       ((0x00000010&(data))>>4)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_cksourcesel(data)                       ((0x00000010&(data))>>4)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_chopfreqsel_shift                           (0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_chopfreqsel_mask                            (0x0000000F)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_chopfreqsel(data)                           (0x0000000F&((data)<<0))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_reg_chopfreqsel_src(data)                       ((0x0000000F&(data))>>0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL2_get_reg_chopfreqsel(data)                       ((0x0000000F&(data))>>0)

#define SC_WRAP_DVFS_TM_SENSOR_CTRL3                                                 0x5C
#define SC_WRAP_DVFS_TM_SENSOR_CTRL3_reg_addr                                        "0x9801D15C"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL3_reg                                             0x9801D15C
#define set_SC_WRAP_DVFS_TM_SENSOR_CTRL3_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL3_reg)=data)
#define get_SC_WRAP_DVFS_TM_SENSOR_CTRL3_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL3_reg))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL3_inst_adr                                        "0x0057"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL3_inst                                            0x0057
#define SC_WRAP_DVFS_TM_SENSOR_CTRL3_reg_offset_shift                                (0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL3_reg_offset_mask                                 (0x003FFFFF)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL3_reg_offset(data)                                (0x003FFFFF&((data)<<0))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL3_reg_offset_src(data)                            ((0x003FFFFF&(data))>>0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL3_get_reg_offset(data)                            ((0x003FFFFF&(data))>>0)

#define SC_WRAP_DVFS_TM_SENSOR_CTRL4                                                 0x60
#define SC_WRAP_DVFS_TM_SENSOR_CTRL4_reg_addr                                        "0x9801D160"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL4_reg                                             0x9801D160
#define set_SC_WRAP_DVFS_TM_SENSOR_CTRL4_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL4_reg)=data)
#define get_SC_WRAP_DVFS_TM_SENSOR_CTRL4_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL4_reg))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL4_inst_adr                                        "0x0058"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL4_inst                                            0x0058
#define SC_WRAP_DVFS_TM_SENSOR_CTRL4_reg_r_shift                                     (0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL4_reg_r_mask                                      (0x00FFFFFF)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL4_reg_r(data)                                     (0x00FFFFFF&((data)<<0))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL4_reg_r_src(data)                                 ((0x00FFFFFF&(data))>>0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL4_get_reg_r(data)                                 ((0x00FFFFFF&(data))>>0)

#define SC_WRAP_DVFS_TM_SENSOR_CTRL5                                                 0x64
#define SC_WRAP_DVFS_TM_SENSOR_CTRL5_reg_addr                                        "0x9801D164"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL5_reg                                             0x9801D164
#define set_SC_WRAP_DVFS_TM_SENSOR_CTRL5_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL5_reg)=data)
#define get_SC_WRAP_DVFS_TM_SENSOR_CTRL5_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_CTRL5_reg))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL5_inst_adr                                        "0x0059"
#define SC_WRAP_DVFS_TM_SENSOR_CTRL5_inst                                            0x0059
#define SC_WRAP_DVFS_TM_SENSOR_CTRL5_reg_s_shift                                     (0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL5_reg_s_mask                                      (0x007FFFFF)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL5_reg_s(data)                                     (0x007FFFFF&((data)<<0))
#define SC_WRAP_DVFS_TM_SENSOR_CTRL5_reg_s_src(data)                                 ((0x007FFFFF&(data))>>0)
#define SC_WRAP_DVFS_TM_SENSOR_CTRL5_get_reg_s(data)                                 ((0x007FFFFF&(data))>>0)

#define SC_WRAP_DVFS_TM_SENSOR_STATUS1                                               0x68
#define SC_WRAP_DVFS_TM_SENSOR_STATUS1_reg_addr                                      "0x9801D168"
#define SC_WRAP_DVFS_TM_SENSOR_STATUS1_reg                                           0x9801D168
#define set_SC_WRAP_DVFS_TM_SENSOR_STATUS1_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_STATUS1_reg)=data)
#define get_SC_WRAP_DVFS_TM_SENSOR_STATUS1_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_STATUS1_reg))
#define SC_WRAP_DVFS_TM_SENSOR_STATUS1_inst_adr                                      "0x005A"
#define SC_WRAP_DVFS_TM_SENSOR_STATUS1_inst                                          0x005A
#define SC_WRAP_DVFS_TM_SENSOR_STATUS1_ct_out_shift                                  (0)
#define SC_WRAP_DVFS_TM_SENSOR_STATUS1_ct_out_mask                                   (0x0007FFFF)
#define SC_WRAP_DVFS_TM_SENSOR_STATUS1_ct_out(data)                                  (0x0007FFFF&((data)<<0))
#define SC_WRAP_DVFS_TM_SENSOR_STATUS1_ct_out_src(data)                              ((0x0007FFFF&(data))>>0)
#define SC_WRAP_DVFS_TM_SENSOR_STATUS1_get_ct_out(data)                              ((0x0007FFFF&(data))>>0)

#define SC_WRAP_DVFS_TM_SENSOR_STATUS2                                               0x6C
#define SC_WRAP_DVFS_TM_SENSOR_STATUS2_reg_addr                                      "0x9801D16C"
#define SC_WRAP_DVFS_TM_SENSOR_STATUS2_reg                                           0x9801D16C
#define set_SC_WRAP_DVFS_TM_SENSOR_STATUS2_reg(data)   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_STATUS2_reg)=data)
#define get_SC_WRAP_DVFS_TM_SENSOR_STATUS2_reg   (*((volatile unsigned int*) SC_WRAP_DVFS_TM_SENSOR_STATUS2_reg))
#define SC_WRAP_DVFS_TM_SENSOR_STATUS2_inst_adr                                      "0x005B"
#define SC_WRAP_DVFS_TM_SENSOR_STATUS2_inst                                          0x005B
#define SC_WRAP_DVFS_TM_SENSOR_STATUS2_u_out_shift                                   (0)
#define SC_WRAP_DVFS_TM_SENSOR_STATUS2_u_out_mask                                    (0x003FFFFF)
#define SC_WRAP_DVFS_TM_SENSOR_STATUS2_u_out(data)                                   (0x003FFFFF&((data)<<0))
#define SC_WRAP_DVFS_TM_SENSOR_STATUS2_u_out_src(data)                               ((0x003FFFFF&(data))>>0)
#define SC_WRAP_DVFS_TM_SENSOR_STATUS2_get_u_out(data)                               ((0x003FFFFF&(data))>>0)

#endif
