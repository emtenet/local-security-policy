#ifndef UNICODE
#define UNICODE
#endif

#include <stdarg.h>
#include <stdio.h>
#include <windows.h>
#include <ntdef.h>
#include <ntsecapi.h>

typedef struct _LSA_ACCOUNT
{
  SID_NAME_USE  use;
  WCHAR         domain[100];
  WCHAR         name[100];
} LSA_ACCOUNT, *PLSA_ACCOUNT;

void print_string(LPCWSTR format, ...)
{
  if (format)
  {
    va_list args;

    va_start(args, format);
    vwprintf(format, args);
    va_end(args);
  }
}

BOOL print_error(LPCWSTR format, ...)
{
  if (format)
  {
    va_list args;

    va_start(args, format);
    vwprintf(format, args);
    va_end(args);
  }

  return FALSE;
}

void print_lsa_string(LSA_UNICODE_STRING* lsa_string)
{
  if (!lsa_string)
    return;

  wprintf(L"%.*s", lsa_string->Length, lsa_string->Buffer);
}

BOOL win_error(ULONG error, LPCTSTR function)
{
  LPCTSTR message = NULL;

  if (!FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS
                    , NULL
                    , error
                    , MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
                    , (LPTSTR)&message
                    , 0
                    , NULL))
  {
    message = L"Error message not found";
  }

  return print_error(L"Error #%lu in %s: %s", error, function, message);
}

BOOL lsa_error(NTSTATUS nt_status, LPCTSTR function)
{
  return win_error(LsaNtStatusToWinError(nt_status), function);
}

BOOL lsa_string_constant(LSA_UNICODE_STRING* lsa_string, LPCWSTR constant)
{
  DWORD length = 0;

  if (NULL == lsa_string)
    return print_error(L"Error in lsa_string_constant: string is NULL.\n");

  if (NULL != constant) 
  {
    length = wcslen(constant);
    if (length > 0x7ffe)
      return print_error(L"Error in lsa_string_constant: constant to long.\n");
  }

  lsa_string->Buffer = (WCHAR *)constant;
  lsa_string->Length =  (USHORT)length * sizeof(WCHAR);
  lsa_string->MaximumLength= (USHORT)(length+1) * sizeof(WCHAR);

  return TRUE;
}

BOOL lsa_open(LSA_HANDLE* lsa_handle)
{
  LSA_OBJECT_ATTRIBUTES object_attributes;
  NTSTATUS              nt_status;

  *lsa_handle = NULL;
  ZeroMemory(&object_attributes, sizeof(object_attributes));
  nt_status = LsaOpenPolicy(NULL, &object_attributes, POLICY_ALL_ACCESS, lsa_handle);
  if (nt_status != STATUS_SUCCESS)
    return lsa_error(nt_status, L"LsaOpenPolicy");
  return TRUE;
}

void lsa_close(LSA_HANDLE lsa_handle)
{
  LsaClose(lsa_handle);
}

BOOL copy_lsa_string_to_wchar(WCHAR* destination, size_t available, LSA_UNICODE_STRING* string)
{
  if (destination == 0)
    return print_error(L"Error in copy_lsa_string_to_wchar: destination is NULL.\n");

  if (available < 1)
    return print_error(L"Error in copy_lsa_string_to_wchar: available < 1.\n");

  if (string == 0 || string->Buffer == 0 || string->Length < 1)
  {
    destination[0] = 0;
    return TRUE;
  }

  wcsncpy(destination, string->Buffer, available < string->Length ? available : string->Length);

  return TRUE;
}

void print_account(PLSA_ACCOUNT account)
{
  if (account == NULL)
    return;

  if (account->use == SidTypeUser)
    print_string(L"user ");
  else if (account->use == SidTypeAlias)
    print_string(L"alias ");

  if (account->domain[0])
    print_string(L"%s\\", account->domain);
  print_string(L"%s", &account->name);
}

BOOL lsa_account_from_sid(LSA_HANDLE lsa_handle, PSID sid, PLSA_ACCOUNT account)
{
  LSA_REFERENCED_DOMAIN_LIST*   domain = 0;
  LSA_TRANSLATED_NAME*          name = 0;
  NTSTATUS                      nt_status;
  BOOL                          success;

  if (sid == NULL)
    return print_error(L"Error in lsa_account_from_sid: sid is NULL.\n");

  if (account == NULL)
    return print_error(L"Error in lsa_account_from_sid: account is NULL.\n");

  nt_status = LsaLookupSids(lsa_handle, 1, &sid, &domain, &name);
  if (nt_status!=STATUS_SUCCESS)
    return lsa_error(nt_status, L"LsaLookupSids");

  account->use = name->Use;

  if (name->DomainIndex >= 0 && name->DomainIndex < domain->Entries)
    success = copy_lsa_string_to_wchar(account->domain, sizeof(account->domain), &domain->Domains[name->DomainIndex].Name);
  else
    success = copy_lsa_string_to_wchar(account->domain, sizeof(account->domain), NULL);

  success &= copy_lsa_string_to_wchar(account->name, sizeof(account->name), &name->Name);

  LsaFreeMemory(domain);
  LsaFreeMemory(name);

  return success;
}

BOOL make_relative_sid(PSID* answer, PSID base, ULONG relative_id)
{
  int     count;
  int     i;

  if (answer == NULL)
    return print_error(L"Error in make_relative_sid: answer is NULL.\n");

  if (base == NULL)
    return print_error(L"Error in make_relative_sid: base is NULL.\n");

  if (!IsValidSid(base))
    return print_error(L"Error in make_relative_sid: base is not a valid SID.\n");

  count = *GetSidSubAuthorityCount(base);
  if (count > 7)
    return print_error(L"Error in make_relative_sid: base has too many sub-authorities.\n");

  if (!AllocateAndInitializeSid( GetSidIdentifierAuthority(base)
                               , 1 + count
                               , 0, 0, 0, 0, 0, 0, 0, 0, answer))
    return win_error(GetLastError(), L"AllocateAndInitializeSid");

  for(i=0; i<count; i++)
  {
    *GetSidSubAuthority(*answer, i) = *GetSidSubAuthority(base, i);
  }

  *GetSidSubAuthority(*answer, count) = relative_id;

  return TRUE;
}

BOOL valid_user(LSA_HANDLE lsa_handle, PSID* answer, LPTSTR constant)
{
  LSA_REFERENCED_DOMAIN_LIST*   domain = 0;
  LUID                          luid;
  NTSTATUS                      nt_status;
  LSA_TRANSLATED_SID*           sid = 0;
  BOOL                          success;
  LSA_UNICODE_STRING            user;

  if (!lsa_string_constant(&user, constant))
    return FALSE;

  nt_status = LsaLookupNames(lsa_handle, 1, &user, &domain, &sid);
  if (nt_status != STATUS_SUCCESS)
    return lsa_error(nt_status, L"LsaLookupNames");

  if (sid->Use != SidTypeUser)
  {
    success = print_error(L"Error: expecting <user>");
  }
  else if (sid->DomainIndex < 0 || sid->DomainIndex > domain->Entries)
  {
    success = print_error(L"Error: LsaLookupNames domain index out of range.");
  }
  else
  {
    success = make_relative_sid(answer, domain->Domains[sid->DomainIndex].Sid, sid->RelativeId);
  }

  LsaFreeMemory(domain);
  LsaFreeMemory(sid);

  return success;
}

BOOL valid_privilege(LSA_UNICODE_STRING *privilege, LPTSTR constant)
{
  LUID    luid;

  if (!lsa_string_constant(privilege, constant))
    return FALSE;

  if (0 == LookupPrivilegeValue(NULL, constant, &luid))
    return print_error(L"Error: Invalid privilege, %s.\n", constant);

  return TRUE;
}

BOOL lsp_list_by_privilege(LSA_HANDLE lsa_handle, LPTSTR privilegeConstant)
{
  LSA_ACCOUNT                   account;
  LSA_ENUMERATION_INFORMATION*  array;
  ULONG                         count;
  ULONG                         i;
  NTSTATUS                      nt_status;
  LSA_UNICODE_STRING            privilege;
  BOOL                          success = TRUE;

  if (!valid_privilege(&privilege, privilegeConstant))
    return FALSE;

  print_string(L"Accounts with %s:\n", privilegeConstant);

  nt_status = LsaEnumerateAccountsWithUserRight(lsa_handle, &privilege, (void**)&array, &count);
  if (nt_status != STATUS_SUCCESS)
    return lsa_error(nt_status, L"LsaEnumerateAccountsWithUserRight");

  for(i=0; i<count; i++)
  {    
    if (!lsa_account_from_sid(lsa_handle, array[i].Sid, &account))
    {
      success = FALSE;
      break;
    }

    print_string(L" - ");
    print_account(&account);
    print_string(L"\n");
  }

  LsaFreeMemory(array);
  return TRUE;
}

BOOL lsp_list_by_user(LSA_HANDLE lsa_handle, LPTSTR user)
{
  LSA_ACCOUNT         account;
  LSA_UNICODE_STRING* array;
  ULONG               count;
  ULONG               i;
  NTSTATUS            nt_status;
  PSID                sid;

  if (!valid_user(lsa_handle, &sid, user))
    return FALSE;

  if (!lsa_account_from_sid(lsa_handle, sid, &account))
  {
    FreeSid(sid);
    return FALSE;
  }

  print_string(L"Privileges for ");
  print_account(&account);
  print_string(L":\n");

  nt_status = LsaEnumerateAccountRights(lsa_handle, sid, &array, &count);
  if (nt_status != STATUS_SUCCESS)
  {
    FreeSid(sid);
    return lsa_error(nt_status, L"LsaEnumerateAccountRights");
  }

  for(i=0; i<count; i++)
  {    
    print_string(L" - ");
    print_lsa_string(&array[i]);
    print_string(L"\n");
  }

  LsaFreeMemory(array);
  FreeSid(sid);

  return TRUE;
}

BOOL lsp_add(LSA_HANDLE lsa_handle, LPTSTR user, LPTSTR privilegeConstant)
{
  LSA_ACCOUNT         account;
  NTSTATUS            nt_status;
  LSA_UNICODE_STRING  privilege;
  PSID                sid;
  BOOL                success = TRUE;

  if (!valid_privilege(&privilege, privilegeConstant))
    return FALSE;

  if (!valid_user(lsa_handle, &sid, user))
    return FALSE;

  if (!lsa_account_from_sid(lsa_handle, sid, &account))
  {
    FreeSid(sid);
    return FALSE;
  }

  print_string(L"Adding %s to ", privilegeConstant);
  print_account(&account);
  print_string(L".\n");

  nt_status = LsaAddAccountRights(lsa_handle, sid, &privilege, 1);
  if (nt_status != STATUS_SUCCESS)
  {
    FreeSid(sid);
    return lsa_error(nt_status, L"LsaAddAccountRights");
  }

  FreeSid(sid);

  return TRUE;
}

BOOL lsp_remove(LSA_HANDLE lsa_handle, LPTSTR user, LPTSTR privilegeConstant)
{
  LSA_ACCOUNT         account;
  NTSTATUS            nt_status;
  LSA_UNICODE_STRING  privilege;
  PSID                sid;
  BOOL                success = TRUE;

  if (!valid_privilege(&privilege, privilegeConstant))
    return FALSE;

  if (!valid_user(lsa_handle, &sid, user))
    return FALSE;

  if (!lsa_account_from_sid(lsa_handle, sid, &account))
  {
    FreeSid(sid);
    return FALSE;
  }

  print_string(L"Removing %s from ", privilegeConstant);
  print_account(&account);
  print_string(L".\n");

  nt_status = LsaRemoveAccountRights(lsa_handle, sid, FALSE, &privilege, 1);
  if (nt_status != STATUS_SUCCESS)
  {
    FreeSid(sid);
    return lsa_error(nt_status, L"LsaRemoveAccountRights");
  }

  FreeSid(sid);

  return TRUE;
}

BOOL lsp_command(LSA_HANDLE lsa_handle, int argc, LPWSTR* argv)
{
  if (argc < 2)
  {
    print_string(L"Manage local security policy\n");
    print_string(L"\n");
    print_string(L"LSP /P <privilege>            List accounts with privilege\n");
    print_string(L"\n");
    print_string(L"LSP /U <user>                 List privileges for user\n");
    print_string(L"\n");
    print_string(L"LSP /A <user> <privilege>     Add privilege to user\n");
    print_string(L"\n");
    print_string(L"LSP /R <user> <privilege>     Remove privilege from user\n");
    return FALSE;
  }

  if (wcscmp(argv[1], L"/P") == 0)
  {
    if (argc > 3)
      return print_error(L"Error: Too many arguments after /P");

    if (argc < 3)
      return print_error(L"Error: missing <privilege> after /P");

    return lsp_list_by_privilege(lsa_handle, argv[2]);
  }

  if (wcscmp(argv[1], L"/U") == 0)
  {
    if (argc > 3)
      return print_error(L"Error: Too many arguments after /U");

    if (argc < 3)
      return print_error(L"Error: missing <user> after /U");

    return lsp_list_by_user(lsa_handle, argv[2]);
  }

  if (wcscmp(argv[1], L"/A") == 0)
  {
    if (argc > 4)
      return print_error(L"Error: Too many arguments after /A");

    if (argc < 3)
      return print_error(L"Error: missing <user> after /A");

    if (argc < 4)
      return print_error(L"Error: missing <privilege> after /A <user>");

    return lsp_add(lsa_handle, argv[2], argv[3]);
  }


  if (wcscmp(argv[1], L"/R") == 0)
  {
    if (argc > 4)
      return print_error(L"Error: Too many arguments after /R");

    if (argc < 3)
      return print_error(L"Error: missing <user> after /R");

    if (argc < 4)
      return print_error(L"Error: missing <privilege> after /R <user>");

    return lsp_remove(lsa_handle, argv[2], argv[3]);
  }

  return print_error(L"Error: Invalid switch %s\n", argv[1]);
}

BOOL lsp(LSA_HANDLE lsa_handle)
{
  LPTSTR  command_line;
  LPWSTR* command_argv;
  int     command_argc;
  BOOL    success;

  command_line = GetCommandLineW();
  command_argv = CommandLineToArgvW(command_line, &command_argc);

  if (command_argv == NULL)
    success = win_error(GetLastError(), L"CommandLineToArgvW");
  else
    success = lsp_command(lsa_handle, command_argc, command_argv);

  LocalFree(command_argv);

  return success ? 0 : 1;
}

int main(void)
{
  LSA_HANDLE  lsa_handle;
  BOOL        success;

  if (!lsa_open(&lsa_handle))
    return 1;

  success = lsp(lsa_handle);

  lsa_close(lsa_handle);
  return success ? 0 : 1;
}