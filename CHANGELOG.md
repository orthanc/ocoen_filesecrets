0.2.0
=====

Core
----

* New `is_encrypted` method to determine if a give byte stream is an encrypted package.

Command Line Interface
----------------------

* Support providing additional data using the `--additional-data' / '-d' options.
* Support providing passwords as argument / file / stdin using the `--password` / `--password-file` options.

File Format
-----------

* **BREAKING CHANGE** replace format version identifier with a 4 byte random identifier to allow it to be used
  to differentiate encrypted package from other files.

Bugfixes
--------

* Add pkgutil to ocoen namespace package to avoid issues with multiple ocoen modules.
