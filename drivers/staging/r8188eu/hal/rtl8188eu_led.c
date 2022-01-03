// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2007 - 2011 Realtek Corporation. */

#include "../include/osdep_service.h"
#include "../include/drv_types.h"
#include "../include/rtl8188e_hal.h"
#include "../include/rtl8188e_led.h"

/*  LED object. */

void SwLedOn(struct adapter *padapter, struct LED_871x *pLed)
{
	u8	LedCfg;

	if (padapter->bSurpriseRemoved || padapter->bDriverStopped)
		return;

	LedCfg = rtw_read8(padapter, REG_LEDCFG2);
	rtw_write8(padapter, REG_LEDCFG2, (LedCfg & 0xf0) | BIT(5) | BIT(6)); /*  SW control led0 on. */
	pLed->bLedOn = true;
}

void SwLedOff(struct adapter *padapter, struct LED_871x *pLed)
{
	u8	LedCfg;

	if (padapter->bSurpriseRemoved || padapter->bDriverStopped)
		goto exit;

	LedCfg = rtw_read8(padapter, REG_LEDCFG2);/* 0x4E */

	LedCfg &= 0x90; /*  Set to software control. */
	rtw_write8(padapter, REG_LEDCFG2, (LedCfg | BIT(3)));
	LedCfg = rtw_read8(padapter, REG_MAC_PINMUX_CFG);
	LedCfg &= 0xFE;
	rtw_write8(padapter, REG_MAC_PINMUX_CFG, LedCfg);
exit:
	pLed->bLedOn = false;
}

/*  Interface to manipulate LED objects. */
/*  Default LED behavior. */

/*	Description: */
/*		Initialize all LED_871x objects. */
void rtl8188eu_InitSwLeds(struct adapter *padapter)
{
	struct led_priv *pledpriv = &padapter->ledpriv;

	pledpriv->LedControlHandler = LedControl8188eu;

	InitLed871x(padapter, &pledpriv->SwLed0);
}

/*	Description: */
/*		DeInitialize all LED_819xUsb objects. */
void rtl8188eu_DeInitSwLeds(struct adapter *padapter)
{
	struct led_priv	*ledpriv = &padapter->ledpriv;

	DeInitLed871x(&ledpriv->SwLed0);
}
