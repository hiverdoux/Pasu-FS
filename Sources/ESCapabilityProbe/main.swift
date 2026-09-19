import Darwin
import EndpointSecurity
import Foundation

private func name(of result: es_new_client_result_t) -> String {
  switch result {
  case ES_NEW_CLIENT_RESULT_SUCCESS:
    "SUCCESS"
  case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
    "ERR_INVALID_ARGUMENT"
  case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
    "ERR_INTERNAL"
  case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
    "ERR_NOT_ENTITLED"
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
    "ERR_NOT_PERMITTED"
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
    "ERR_NOT_PRIVILEGED"
  case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
    "ERR_TOO_MANY_CLIENTS"
  default:
    "UNKNOWN(\(result.rawValue))"
  }
}

private func explanation(of result: es_new_client_result_t) -> String {
  switch result {
  case ES_NEW_CLIENT_RESULT_SUCCESS:
    "Endpoint Security client creation succeeded; the probe will delete it immediately."
  case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
    "The executable is not authorized for the Endpoint Security client entitlement."
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
    "Endpoint Security access is not permitted by the current privacy authorization."
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
    "The process does not have the privilege required for a system-wide Endpoint Security client."
  default:
    "See Apple's es_new_client_result_t documentation for this result."
  }
}

print("Pasu FS Endpoint Security capability probe")

var client: OpaquePointer?
let result = es_new_client(&client) { _, _ in
  // This probe never subscribes to events. The handler should not be called.
}

print("es_new_client result: \(name(of: result))")
print(explanation(of: result))

if result == ES_NEW_CLIENT_RESULT_SUCCESS, let client {
  _ = es_delete_client(client)
}

let expectedPreapprovalResult =
  result == ES_NEW_CLIENT_RESULT_SUCCESS
  || result == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED
  || result == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED
  || result == ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED

exit(expectedPreapprovalResult ? EXIT_SUCCESS : EXIT_FAILURE)
