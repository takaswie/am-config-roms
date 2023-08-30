==================================================
Configuration ROM images for node in IEEE 1394 bus
==================================================

2023/02/06 Takashi Sakamoto

Description
===========

* This repository is collection of configuration ROM images for node in IEEE 1394 bus, which mainly includes audio and music units.
* At present, the purpose of the repository is to generate hardware database in systemd project.

  * https://www.freedesktop.org/software/systemd/man/hwdb.html
  * A Python 3 script (hwdb-entry-generator) is available to generate database entry.

* The collected images are categorized according to its functionality. At present:

  * audio and music

    * node includes unit relevant to audio signal processing and musical messaging

  * video and audio

    * node includes unit relevant to video signal processing and audio signal processing

  * video

    * node includes unit relevant to video signal processing

  * composite

    * node includes several units

``audio_and_music/bebob``
=========================

* BridgeCo. Enhanced Break Out Box (BeBoB), supported by ``snd-bebob``

  * Apogee Ensemble
  * Avid Mbox 2 Pro
  * Behringer FCA 610
  * Behringer FCA 1616
  * Behringer UFX 1204
  * Behringer UFX 1604
  * Behringer X-UF extension card for X32
  * Edirol FA-66
  * ESI Quatafire 610
  * Focusrite Saffire
  * Focusrite Saffire LE
  * Focusrite Saffire Pro 10 I/O
  * Focusrite Saffire Pro 26 I/O
  * Mackie Onyx FireWire
  * M-Audio FireWire Audiophile
  * M-Audio FireWire 1814
  * M-Audio FireWire 410
  * M-Audio Ozonic
  * M-Audio Profire LightBridge
  * M-Audio FireWire Solo
  * Ponic FireFly 202
  * PreSonus FirePod
  * PreSonus Inspire1394
  * Stanton Final Scratch
  * Tascam IF-FW/DM
  * Terratec Phase 24x
  * Yamaha GO44
  * Yamaha GO46

``audio_and_music/dice``
========================

* TC Applied Technologies Digital Interface Communication Engine (DICE), supported by ``snd-dice``

  * Alesis MasterControl
  * Alesis IO|14
  * Alesis IO|26
  * Alesis MultiMix12 FireWire
  * Avid Mbox 3 Pro
  * FlexRadio FLEX-3000
  * Focusrite Liquid Saffire 56
  * Focusrite SaffirePro 14
  * Focusrite SaffirePro 24
  * Focusrite SaffirePro 24 DSP
  * Focusrite SaffirePro 26
  * Focusrite SaffirePro 40 (with TCD2210)
  * Focusrite SaffirePro 40 (with TCD3070)
  * Lexicon I-ONIX Fw810s (I-O FW810s)
  * Mackie Blackbird
  * Mackie Onyx-i (latter models)
  * Midas VenicheF
  * Mytek Stereo192-DSD DAC
  * M-Audio Profire 610
  * M-Audio Profire 2626
  * PreSonus FireStudio
  * PreSonus FireStudio Mobile
  * PreSonus FireStudio Project
  * PreSonus FireStudio Tube
  * PreSonus StudioLive 16.4.2
  * PreSonus StudioLive 24.4.2
  * PreSonus StudioLive 32.4.2 AI
  * Solid State Logic Duende Classic
  * Solid State Logic Duende Mini
  * TC Electronic Desktop Konnekt 6
  * TC Electronic Digital Konnekt x32
  * TC Electronic Impact Twin
  * TC Electronic Konnekt 24d
  * TC Electronic Konnekt 8
  * TC Electronic KonnektLive
  * TC Electronic Studio Konnekt 48
  * Weiss MAN301
  * Weiss DAC202
  * Weiss INT202
  * Weiss INT203
  * Weiss AFI1
  * Weiss ADC2
  * Weiss DAC2/Minerva
  * Weiss Vesta

``audio_and_music/fireworks``
=============================

* Echo Audio Fireworks board module, supported by ``snd-fireworks``

  * Echo Audio AudioFire 2
  * Echo Audio AudioFire 4
  * Echo Audio Audiofire 8 (till Jul 2009)
  * Echo Audio Audiofire 8 (since Jul 2009)
  * Echo Audio AudioFire pre8
  * Echo Audio AudioFire 12
  * Gibson Robot Interface Pack
  * Mackie Onyx 400F
  * Mackie Onyx 1200F

``audio_and_music/oxfw``
========================

* Oxford Semiconductor FW970/971 ASICs, supported by ``snd-oxfw``

  * Apogee Duet FireWire
  * Behringer F-Control Audio 202
  * Griffin FireWave
  * Mackie Onyx 820i
  * Mackie Onyx 1640i
  * Mackie Onyx Sattelite
  * Mackie Tapco Link.FireWire 4x6
  * Stanton SCS.1m
  * Stanton SCS.1d
  * Tascam FireOne

``audio_and_music/digi00x``
===========================

* Digidesign Digi00x family, supported by ``snd-firewire-digi00x``

  * Digi 002
  * Digi 002 rack
  * Digi 003
  * Digi 003 rack

``audio_and_music/tascam``
==========================

* TASCAM FireWire series, supported by ``snd-firewire-tascam``

  * FW-1082
  * FW-1804
  * FW-1884

* TASCAM FireWire series, supported by ``snd-firewire-ctl-services``

  * FE-8

``audio_and_music/motu``
========================

* Mark of the Unicorn (MOTU) FireWire series, supported by ``snd-firewire-motu``

  * MOTU 828
  * MOTU 828mkII
  * MOTU 828mk3 FireWire
  * MOTU 828mk3 Hybrid
  * MOTU 896
  * MOTU 896 HD
  * MOTU 896 mk3 FireWire
  * MOTU 896 mk3 Hybrid
  * MOTU 8pre
  * MOTU AudioExpress
  * MOTU Traveler
  * MOTU Traveler mk3
  * MOTU 4pre
  * MOTU Ultralite
  * MOTU Ultralite mk3 FireWire
  * MOTU Ultralite mk3 Hybrid
  * MOTU Track 16

``audio_and_music/fireface``
============================

* RME Fireface series, supported by ``snd-fireface``

  * Fireface 400
  * Fireface 800
  * Fireface UCX
  * Fireface 802

``audio_and_music``
===================

* Neither supported by userspace applications nor kernel drivers

  * Focusrite Liquid Mix 16
  * Focusrite Liquid Mix 32
  * TC Electronic PowerCore FireWire
  * TC Electronic PowerCore Compact
  * Yamaha mLAN 2nd generation

    * Yamaha i88x
    * Yamaha 01x
    * PreSonus FireStudio

  * Yamaha mLAN 3rd generation

    * Yamaha n8
    * Steinberg MR816x

``video_and_audio``
===================

* Neither supported by userspace applications nor kernel drivers

  * Avid Adrenaline
  * Avid Mojo

``video``
=========

* video functionality is supported by userspace applications

  * Basler A602f
  * Cool Stream iSweet
  * Dage-MTI Excel XL16C
  * Hamamatsu Photonics C8484-05G
  * Point Grey Research Flea2 FL2-08S2C
  * Point Grey Research Grasshopper GRAS-50S5C
  * Sony DCR-TRV310K (Digital8)
  * The Imaging Source Europe DBM 21BF04
  * The Imaging Source Europe DMM 32BF04

``composite``
=============

* Apple iSight

  * audio functionality is supported by ``snd-isight``
  * video functionality is supported by userspace applications

* MOTU V4HD

  * Nothing supported at present

* AJA Io HD
* AJA Io LD

  * Nothing supported at present.

end
