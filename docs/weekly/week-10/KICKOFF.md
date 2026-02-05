
# Week 10 Kickoff: App Roles Discovery

**Goal:** Discover and track custom application roles assigned to service principals

**Estimated Time:** 8 hours

---

## 🎯 What We're Building

### **The Problem:**
Currently, we see:
- ✅ Azure RBAC roles (Owner, Contributor)
- ✅ API permissions (User.Read.All)
- ❌ App roles (custom roles defined in applications)

### **What Are App Roles?**
```
Example Application: "MyCompanyApp"
App Roles:
- Admin (full access)
- Viewer (read-only)
- DataProcessor (can process data)
- ReportReader (can read reports)
```

**Why This Matters:**
- SPNs often have app roles instead of Azure RBAC
- These grant access to specific application functionality
- Critical for complete access visibility

---

## 📋 Implementation Steps

### **Step 1: Update Discovery Engine**
- Add `_discover_app_roles()` method
- Fetch from: `/servicePrincipals/{id}/appRoleAssignedTo`
- Parse and structure role data

### **Step 2: Create Database Table**
- Table: `sp_app_roles`
- Store: role value, display name, resource, risk level

### **Step 3: Integrate with Main Flow**
- Call after API permissions discovery
- Store in database
- Include in `_save_identities()`

### **Step 4: Update API Response**
- Add `app_roles` array to GET /api/identities/{id}

### **Step 5: Test & Validate**
- Test with SPNs that have app roles
- Verify database storage
- Check API response

---

## ✅ Ready to Start?

Reply: **"Let's start Week 10 - App Roles Discovery!"**

And we'll begin step-by-step implementation! 🚀
KICKOFF

echo "✅ Week 10 Kickoff document created!"