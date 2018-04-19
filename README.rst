Secure96
########

`Secure96 <https://www.96boards.org/product/secure96/>`_ is a mezzanine board
containing a couple of different Integrated Circuits used for secure computing.

.. contents::

.. section-numbering::

ATSHA204A
=========
ATSHA204A is an Integrated Circuit that can be used in designs where symmetric
encryption is an alternative. It also features built-in random number generator
among other things. For more information about this IC and what it is capable
of, please see the datasheet further down.

Build instructions
------------------
.. code-block:: bash

	$ mkdir -p atsha204a/build
	$ cd atsha204a/build
	$ cmake -DCMAKE_C_COMPILER=arm-linux-gnueabihf-gcc ..

If you are running natively on an Arm device, then you do not have to specify
the `CMAKE_C_COMPILER`.

Datasheet
---------
* Can be found on Microchip's page: http://www.microchip.com/wwwproducts/en/ATsha204a

ATECC508A
==========
TDB - IC for doing asymmetric cryptography.

SLB9670
===========
TDB - This is a TPM from Infineon.
