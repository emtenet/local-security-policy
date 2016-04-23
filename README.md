# local-security-policy

Command line management of Local Security Policy on Windows

Existing tools (gpedit.msc & secpol.msc) allow you to manage Local Secutiry Policies.
But these are not available on all editions of Windows, notably the Home edition.
There are [unsupported](http://drudger.deviantart.com/art/Add-GPEDIT-msc-215792914)
ways to get around this limitation but may be hazaous to your system and may not work anyway.

When you just want to enable one policy on your personal PC even the existing tools can be a bit of overkill.

## Why?

I wanted to use 
[Erlang](http://www.erlang.org/)'s
[file:make_link/2](http://erlang.org/doc/man/file.html#make_symlink-2)
on Windows in the context of
[rebar3](https://www.rebar3.org/)
and
[relx](http://erlware.github.io/relx/) releases.

But, users need *SeCreateSymbolicLinkPrivilege* or *Run as Administrator* to make symbolic links.
This tool allows us to add that privilege with `lsp /A user SeCreateSymbolicLinkPrivilege`.

> **NOTE:** Users in the *Administrators* group are not helped by giving them this privilege
> , they still need to *Run as Administrator* or accept a UAC prompt to make symbolic links.

I am trialing non-Administrator user account (recommended by Windows) with 
*SeCreateSymbolicLinkPrivilege* that gives me easy access to symbolic links 
and a special Administrator user (with its own password) for use when 
elevating to an Administrator.
A bit of extra typing (the admin passwor) when accepting a UAC prompt
, but maybe that is more secure as well.

## The command line

```
> lsp
Manage local security policy

LSP /P <privilege>            List accounts with privilege

LSP /U <user>                 List privileges for user

LSP /A <user> <privilege>     Add privilege to user

LSP /R <user> <privilege>     Remove privilege from user
```

> Remember to use this command inside an elevated command prompt (Run as Administrator).

## Installation

This application can be compiled with
[make](http://gnuwin32.sourceforge.net/packages/make.htm)
and
[gcc](http://tdm-gcc.tdragon.net/)
for Windows.

Clone this repository, run `make` in your cloned folder.

Run the `lsp.exe` directly from your cloned folder or copy it to a folder in your `PATH`.

## Example

This example adds *SeCreateSymbolicLinkPrivilege* to `user` on computer called `USER-PC`.

Insde an elevated command prompt (Run as Administrator), execute:

```
> lsp /A user SeCreateSymbolicLinkPrivilege
Adding SeCreateSymbolicLinkPrivilege to USER-PC\user
```

To apply the new policy immediately, execute:

```
> gpupdate
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

