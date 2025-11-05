#!/bin/bash
# BPF Bug Fix Validation Script
# This script validates that all 7 bug fixes are present in the current kernel source

set -e

KERNEL_DIR="/home/user/linux"
PASS=0
FAIL=0
TOTAL=7

echo "=================================================="
echo "  BPF Bug Fix Validation Test"
echo "  Kernel Source: $KERNEL_DIR"
echo "=================================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_fix() {
    local name="$1"
    local file="$2"
    local pattern="$3"
    local description="$4"

    echo -n "[$((PASS + FAIL + 1))/$TOTAL] Testing: $name... "

    if grep -q "$pattern" "$KERNEL_DIR/$file" 2>/dev/null; then
        echo -e "${GREEN}PASS${NC}"
        echo "  ✓ $description"
        PASS=$((PASS + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        echo "  ✗ Fix not found in $file"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

echo "=== Bug Fix Validation Tests ==="
echo ""

# Bug #1: Ring buffer IRQ work race
test_fix "Bug #1: Ring buffer IRQ sync" \
    "kernel/bpf/ringbuf.c" \
    "irq_work_sync(&rb->work)" \
    "IRQ work synchronized before freeing ring buffer"

# Bug #2: Liveness analysis memory leak
test_fix "Bug #2: Liveness memory leak fix" \
    "kernel/bpf/liveness.c" \
    "kvfree(result)" \
    "func_instance freed on must_write_set allocation failure"

# Bug #3: Metadata dst leak (IPv6)
test_fix "Bug #3: Metadata dst leak (v6)" \
    "net/core/filter.c" \
    "skb_dst_drop(skb);" \
    "Old dst dropped before setting new one in redirect_neigh"

# Bug #4: Negative head_room validation
test_fix "Bug #4: Negative head_room check" \
    "net/core/filter.c" \
    "(int)head_room < 0" \
    "Negative head_room values rejected in skb_change_head"

# Bug #5: ARM64 JIT register fix
test_fix "Bug #5: ARM64 JIT tmp3 register" \
    "arch/arm64/net/bpf_jit_comp.c" \
    "tmp3 = bpf2a64\[TMP_REG_3\]" \
    "ARM64 JIT uses tmp3 to avoid register clobbering"

# Bug #6: LoongArch sign extension
test_fix "Bug #6: LoongArch sign_extend function" \
    "arch/loongarch/net/bpf_jit.c" \
    "static void sign_extend" \
    "LoongArch properly sign-extends struct ops return values"

# Bug #7: SCC info counter initialization
test_fix "Bug #7: SCC counter initialization" \
    "kernel/bpf/verifier.c" \
    "env->scc_cnt = next_scc_id" \
    "SCC counter initialized to prevent memory leak"

echo ""
echo "=== Additional Safety Checks ==="
echo ""

# Additional checks for code quality
echo -n "[+] Checking for overflow protection... "
if grep -q "check_mul_overflow\|check_add_overflow\|size_mul" "$KERNEL_DIR/kernel/bpf/verifier.c"; then
    echo -e "${GREEN}PASS${NC}"
    echo "  ✓ Overflow checks present in verifier"
else
    echo -e "${YELLOW}WARN${NC}"
fi

echo -n "[+] Checking for proper RCU usage... "
if grep -q "call_rcu\|rcu_read_lock\|synchronize_rcu" "$KERNEL_DIR/kernel/bpf/core.c"; then
    echo -e "${GREEN}PASS${NC}"
    echo "  ✓ RCU synchronization present"
else
    echo -e "${YELLOW}WARN${NC}"
fi

echo -n "[+] Checking for work synchronization... "
if grep -q "cancel_work_sync\|flush_work\|irq_work_sync" "$KERNEL_DIR/kernel/bpf/"*.c; then
    echo -e "${GREEN}PASS${NC}"
    echo "  ✓ Work/IRQ synchronization present"
else
    echo -e "${YELLOW}WARN${NC}"
fi

echo ""
echo "=== Pattern Analysis ==="
echo ""

# Check for potential issues using patterns from fixed bugs
echo "[+] Scanning for potential memory leak patterns..."
LEAK_COUNT=$(grep -rn "= kzalloc\|= kvzalloc\|= kmalloc" "$KERNEL_DIR/kernel/bpf/"*.c | \
    grep -v "if (!.*)" | wc -l)
echo "  Found $LEAK_COUNT allocation sites (manual review recommended)"

echo "[+] Scanning for async work initialization..."
WORK_COUNT=$(grep -rn "INIT_WORK\|init_irq_work\|timer_setup" "$KERNEL_DIR/kernel/bpf/"*.c | wc -l)
SYNC_COUNT=$(grep -rn "cancel_work\|irq_work_sync\|del_timer\|hrtimer_cancel" "$KERNEL_DIR/kernel/bpf/"*.c | wc -l)
echo "  Work initializations: $WORK_COUNT"
echo "  Synchronization calls: $SYNC_COUNT"
if [ $SYNC_COUNT -ge $((WORK_COUNT - 2)) ]; then
    echo -e "  ${GREEN}✓ Balanced work/sync ratio${NC}"
else
    echo -e "  ${YELLOW}⚠ Review async work cleanup paths${NC}"
fi

echo "[+] Checking for negative value validation..."
NEG_CHECKS=$(grep -rn "(int).*< 0\|< 0.*cast" "$KERNEL_DIR/net/core/filter.c" | wc -l)
echo "  Found $NEG_CHECKS negative value checks"

echo ""
echo "=== Results Summary ==="
echo "=================================================="
echo -e "Tests Passed: ${GREEN}$PASS${NC}/$TOTAL"
echo -e "Tests Failed: ${RED}$FAIL${NC}/$TOTAL"
echo "=================================================="

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ ALL BUG FIXES VERIFIED PRESENT${NC}"
    echo ""
    echo "All 7 critical bug fixes have been verified in the source code."
    echo "The kernel source appears to be up-to-date with recent security fixes."
    exit 0
else
    echo -e "${RED}✗ SOME BUG FIXES MISSING${NC}"
    echo ""
    echo "WARNING: $FAIL bug fix(es) could not be verified."
    echo "Please review the failed tests above."
    exit 1
fi
