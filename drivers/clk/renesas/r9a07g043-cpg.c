// SPDX-License-Identifier: GPL-2.0
/*
 * RZ/G2UL CPG driver
 *
 * Copyright (C) 2022 Renesas Electronics Corp.
 */

#include <linux/clk-provider.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <dt-bindings/clock/r9a07g043-cpg.h>

#include "rzg2l-cpg.h"

enum clk_ids {
	/* Core Clock Outputs exported to DT */
	LAST_DT_CORE_CLK = R9A07G043_CLK_P0_DIV2,

	/* External Input Clocks */
	CLK_EXTAL,

	/* Internal Core Clocks */
	CLK_OSC_DIV1000,
	CLK_PLL1,
	CLK_PLL2,
	CLK_PLL2_DIV2,
	CLK_PLL2_DIV2_8,
	CLK_PLL3,
	CLK_PLL3_DIV2,
	CLK_PLL3_DIV2_4,
	CLK_PLL3_DIV2_4_2,
	CLK_PLL5,
	CLK_PLL5_500,
	CLK_PLL5_250,
	CLK_PLL6,
	CLK_PLL6_250,
	CLK_P1_DIV2,
	CLK_PLL2_800,
	CLK_PLL2_SDHI_533,
	CLK_PLL2_SDHI_400,
	CLK_PLL2_SDHI_266,
	CLK_SD0_DIV4,
	CLK_SD1_DIV4,

	/* Module Clocks */
	MOD_CLK_BASE,
};

/* Divider tables */
static const struct clk_div_table dtable_1_8[] = {
	{0, 1},
	{1, 2},
	{2, 4},
	{3, 8},
	{0, 0},
};

static const struct clk_div_table dtable_1_32[] = {
	{0, 1},
	{1, 2},
	{2, 4},
	{3, 8},
	{4, 32},
	{0, 0},
};

/* Mux clock tables */
static const char * const sel_pll6_2[]	= { ".pll6_250", ".pll5_250" };
static const char * const sel_shdi[] = { ".clk_533", ".clk_400", ".clk_266" };

static const struct cpg_core_clk r9a07g043_core_clks[] __initconst = {
	/* External Clock Inputs */
	DEF_INPUT("extal", CLK_EXTAL),

	/* Internal Core Clocks */
	DEF_FIXED(".osc", R9A07G043_OSCCLK, CLK_EXTAL, 1, 1),
	DEF_FIXED(".osc_div1000", CLK_OSC_DIV1000, CLK_EXTAL, 1, 1000),
	DEF_SAMPLL(".pll1", CLK_PLL1, CLK_EXTAL, PLL146_CONF(0)),
	DEF_FIXED(".pll2", CLK_PLL2, CLK_EXTAL, 200, 3),
	DEF_FIXED(".pll2_div2", CLK_PLL2_DIV2, CLK_PLL2, 1, 2),
	DEF_FIXED(".clk_800", CLK_PLL2_800, CLK_PLL2, 1, 2),
	DEF_FIXED(".clk_533", CLK_PLL2_SDHI_533, CLK_PLL2, 1, 3),
	DEF_FIXED(".clk_400", CLK_PLL2_SDHI_400, CLK_PLL2_800, 1, 2),
	DEF_FIXED(".clk_266", CLK_PLL2_SDHI_266, CLK_PLL2_SDHI_533, 1, 2),
	DEF_FIXED(".pll2_div2_8", CLK_PLL2_DIV2_8, CLK_PLL2_DIV2, 1, 8),
	DEF_FIXED(".pll3", CLK_PLL3, CLK_EXTAL, 200, 3),
	DEF_FIXED(".pll3_div2", CLK_PLL3_DIV2, CLK_PLL3, 1, 2),
	DEF_FIXED(".pll3_div2_4", CLK_PLL3_DIV2_4, CLK_PLL3_DIV2, 1, 4),
	DEF_FIXED(".pll3_div2_4_2", CLK_PLL3_DIV2_4_2, CLK_PLL3_DIV2_4, 1, 2),
	DEF_FIXED(".pll5", CLK_PLL5, CLK_EXTAL, 125, 1),
	DEF_FIXED(".pll5_500", CLK_PLL5_500, CLK_PLL5, 1, 6),
	DEF_FIXED(".pll5_250", CLK_PLL5_250, CLK_PLL5_500, 1, 2),
	DEF_FIXED(".pll6", CLK_PLL6, CLK_EXTAL, 125, 6),
	DEF_FIXED(".pll6_250", CLK_PLL6_250, CLK_PLL6, 1, 2),

	/* Core output clk */
	DEF_DIV("I", R9A07G043_CLK_I, CLK_PLL1, DIVPL1A, dtable_1_8,
		CLK_DIVIDER_HIWORD_MASK),
	DEF_DIV("P0", R9A07G043_CLK_P0, CLK_PLL2_DIV2_8, DIVPL2A,
		dtable_1_32, CLK_DIVIDER_HIWORD_MASK),
	DEF_DIV("P1", R9A07G043_CLK_P1, CLK_PLL3_DIV2_4,
		DIVPL3B, dtable_1_32, CLK_DIVIDER_HIWORD_MASK),
	DEF_FIXED("P1_DIV2", CLK_P1_DIV2, R9A07G043_CLK_P1, 1, 2),
	DEF_DIV("P2", R9A07G043_CLK_P2, CLK_PLL3_DIV2_4_2,
		DIVPL3A, dtable_1_32, CLK_DIVIDER_HIWORD_MASK),
	DEF_FIXED("M0", R9A07G043_CLK_M0, CLK_PLL3_DIV2_4, 1, 1),
	DEF_FIXED("ZT", R9A07G043_CLK_ZT, CLK_PLL3_DIV2_4_2, 1, 1),
	DEF_MUX("HP", R9A07G043_CLK_HP, SEL_PLL6_2,
		sel_pll6_2, ARRAY_SIZE(sel_pll6_2), 0, CLK_MUX_HIWORD_MASK),
	DEF_SD_MUX("SD0", R9A07G043_CLK_SD0, SEL_SDHI0,
		   sel_shdi, ARRAY_SIZE(sel_shdi)),
	DEF_SD_MUX("SD1", R9A07G043_CLK_SD1, SEL_SDHI1,
		   sel_shdi, ARRAY_SIZE(sel_shdi)),
	DEF_FIXED("SD0_DIV4", CLK_SD0_DIV4, R9A07G043_CLK_SD0, 1, 4),
	DEF_FIXED("SD1_DIV4", CLK_SD1_DIV4, R9A07G043_CLK_SD1, 1, 4),
};

static struct rzg2l_mod_clk r9a07g043_mod_clks[] = {
	DEF_MOD("gic",		R9A07G043_GIC600_GICCLK, R9A07G043_CLK_P1,
				0x514, 0),
	DEF_MOD("ia55_pclk",	R9A07G043_IA55_PCLK, R9A07G043_CLK_P2,
				0x518, 0),
	DEF_MOD("ia55_clk",	R9A07G043_IA55_CLK, R9A07G043_CLK_P1,
				0x518, 1),
	DEF_MOD("dmac_aclk",	R9A07G043_DMAC_ACLK, R9A07G043_CLK_P1,
				0x52c, 0),
	DEF_MOD("dmac_pclk",	R9A07G043_DMAC_PCLK, CLK_P1_DIV2,
				0x52c, 1),
	DEF_MOD("sdhi0_imclk",	R9A07G043_SDHI0_IMCLK, CLK_SD0_DIV4,
				0x554, 0),
	DEF_MOD("sdhi0_imclk2",	R9A07G043_SDHI0_IMCLK2, CLK_SD0_DIV4,
				0x554, 1),
	DEF_MOD("sdhi0_clk_hs",	R9A07G043_SDHI0_CLK_HS, R9A07G043_CLK_SD0,
				0x554, 2),
	DEF_MOD("sdhi0_aclk",	R9A07G043_SDHI0_ACLK, R9A07G043_CLK_P1,
				0x554, 3),
	DEF_MOD("sdhi1_imclk",	R9A07G043_SDHI1_IMCLK, CLK_SD1_DIV4,
				0x554, 4),
	DEF_MOD("sdhi1_imclk2",	R9A07G043_SDHI1_IMCLK2, CLK_SD1_DIV4,
				0x554, 5),
	DEF_MOD("sdhi1_clk_hs",	R9A07G043_SDHI1_CLK_HS, R9A07G043_CLK_SD1,
				0x554, 6),
	DEF_MOD("sdhi1_aclk",	R9A07G043_SDHI1_ACLK, R9A07G043_CLK_P1,
				0x554, 7),
	DEF_COUPLED("eth0_axi",	R9A07G043_ETH0_CLK_AXI, R9A07G043_CLK_M0,
				0x57c, 0),
	DEF_COUPLED("eth0_chi",	R9A07G043_ETH0_CLK_CHI, R9A07G043_CLK_ZT,
				0x57c, 0),
	DEF_COUPLED("eth1_axi",	R9A07G043_ETH1_CLK_AXI, R9A07G043_CLK_M0,
				0x57c, 1),
	DEF_COUPLED("eth1_chi",	R9A07G043_ETH1_CLK_CHI, R9A07G043_CLK_ZT,
				0x57c, 1),
	DEF_MOD("scif0",	R9A07G043_SCIF0_CLK_PCK, R9A07G043_CLK_P0,
				0x584, 0),
	DEF_MOD("scif1",	R9A07G043_SCIF1_CLK_PCK, R9A07G043_CLK_P0,
				0x584, 1),
	DEF_MOD("scif2",	R9A07G043_SCIF2_CLK_PCK, R9A07G043_CLK_P0,
				0x584, 2),
	DEF_MOD("scif3",	R9A07G043_SCIF3_CLK_PCK, R9A07G043_CLK_P0,
				0x584, 3),
	DEF_MOD("scif4",	R9A07G043_SCIF4_CLK_PCK, R9A07G043_CLK_P0,
				0x584, 4),
	DEF_MOD("sci0",		R9A07G043_SCI0_CLKP, R9A07G043_CLK_P0,
				0x588, 0),
	DEF_MOD("sci1",		R9A07G043_SCI1_CLKP, R9A07G043_CLK_P0,
				0x588, 1),
	DEF_MOD("gpio",		R9A07G043_GPIO_HCLK, R9A07G043_OSCCLK,
				0x598, 0),
};

static struct rzg2l_reset r9a07g043_resets[] = {
	DEF_RST(R9A07G043_GIC600_GICRESET_N, 0x814, 0),
	DEF_RST(R9A07G043_GIC600_DBG_GICRESET_N, 0x814, 1),
	DEF_RST(R9A07G043_IA55_RESETN, 0x818, 0),
	DEF_RST(R9A07G043_DMAC_ARESETN, 0x82c, 0),
	DEF_RST(R9A07G043_DMAC_RST_ASYNC, 0x82c, 1),
	DEF_RST(R9A07G043_SDHI0_IXRST, 0x854, 0),
	DEF_RST(R9A07G043_SDHI1_IXRST, 0x854, 1),
	DEF_RST(R9A07G043_ETH0_RST_HW_N, 0x87c, 0),
	DEF_RST(R9A07G043_ETH1_RST_HW_N, 0x87c, 1),
	DEF_RST(R9A07G043_SCIF0_RST_SYSTEM_N, 0x884, 0),
	DEF_RST(R9A07G043_SCIF1_RST_SYSTEM_N, 0x884, 1),
	DEF_RST(R9A07G043_SCIF2_RST_SYSTEM_N, 0x884, 2),
	DEF_RST(R9A07G043_SCIF3_RST_SYSTEM_N, 0x884, 3),
	DEF_RST(R9A07G043_SCIF4_RST_SYSTEM_N, 0x884, 4),
	DEF_RST(R9A07G043_SCI0_RST, 0x888, 0),
	DEF_RST(R9A07G043_SCI1_RST, 0x888, 1),
	DEF_RST(R9A07G043_GPIO_RSTN, 0x898, 0),
	DEF_RST(R9A07G043_GPIO_PORT_RESETN, 0x898, 1),
	DEF_RST(R9A07G043_GPIO_SPARE_RESETN, 0x898, 2),
};

static const unsigned int r9a07g043_crit_mod_clks[] __initconst = {
	MOD_CLK_BASE + R9A07G043_GIC600_GICCLK,
	MOD_CLK_BASE + R9A07G043_IA55_CLK,
	MOD_CLK_BASE + R9A07G043_DMAC_ACLK,
};

const struct rzg2l_cpg_info r9a07g043_cpg_info = {
	/* Core Clocks */
	.core_clks = r9a07g043_core_clks,
	.num_core_clks = ARRAY_SIZE(r9a07g043_core_clks),
	.last_dt_core_clk = LAST_DT_CORE_CLK,
	.num_total_core_clks = MOD_CLK_BASE,

	/* Critical Module Clocks */
	.crit_mod_clks = r9a07g043_crit_mod_clks,
	.num_crit_mod_clks = ARRAY_SIZE(r9a07g043_crit_mod_clks),

	/* Module Clocks */
	.mod_clks = r9a07g043_mod_clks,
	.num_mod_clks = ARRAY_SIZE(r9a07g043_mod_clks),
	.num_hw_mod_clks = R9A07G043_TSU_PCLK + 1,

	/* Resets */
	.resets = r9a07g043_resets,
	.num_resets = R9A07G043_TSU_PRESETN + 1, /* Last reset ID + 1 */
};
