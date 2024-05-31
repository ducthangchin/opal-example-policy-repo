package app.rbac

# import data.utils

# By default, deny requests
default allow = false

# Input data format
# input: {
#     "user": {
#         "roles": ["manager" | "secretary" | "admin" | "accountant"],
#         "id": 131,
#         "manager_id": 123,
#         "subordinate_ids": [11, 12]
#     },
#     "action": "update" | "create" | "update" | "delete" | "access_control",
#     "resource": {
#         "type": "salary" | "document",
#         "id": 12,
#         "created_by": 12,
#         "blocked": false
#     }
# }

# Allow admins to do anything
allow {
	user_is_admin
}

allow {
	some i
	role := input.user.roles[i]
	role == "manager"
	user_has_subordinate(input.resource.created_by)
	action_allow(role)
}

allow {
	some i
	role := input.user.roles[i]
	role == "secretary"
	input.action == "create"
	input.resource.type == "document"
}

allow {
	some i
	role := input.user.roles[i]
	role == "secretary"
	input.action != "create"
	input.resource.type == "document"
	input.resource.blocked == false
	input.resource.created_by == input.user.id
	action_allow(role)
}

allow {
	some i
	role := input.user.roles[i]
	role == "accountant"
	input.action == "create"
	input.resource.type == "salary"
}

allow {
	some i
	role := input.user.roles[i]
	role == "accountant"
	input.action != "create"
	input.resource.type == "salary"
	input.resource.created_by == input.user.id
	action_allow(role)
}

allow {
	some i
	role := input.user.roles[i]
	role == "employee"
	action_allow(role)
}

user_is_admin {
	some i

	# "admin" is the `i`-th element in the user->role mappings for the identified user.
	input.user.roles[i] == "admin"
}

# # user_is_granted is a set of permissions for the user identified in the request.
# # The `permission` will be contained if the set `user_is_granted` for every...
action_allow(role) {
	some i
	permission := data.role_permissions[role][i]
	permission.action == input.action
	permission.type == input.resource.type
}

user_has_subordinate(subordinate_id) {
	some i
	input.user.subordinate_ids[i] == subordinate_id
}
