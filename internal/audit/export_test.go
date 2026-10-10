// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

// Actions lists every declared action. TestActions_ListsEveryDeclaredAction keeps
// it complete, so that the store test writes every action to the database.
var Actions = []Action{
	ActionUserCreate,
}
