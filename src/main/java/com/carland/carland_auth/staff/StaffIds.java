package com.carland.carland_auth.staff;

/**
 * Staff account ids stay in their own range so they cannot equal a customer {@code users.id}.
 */
public final class StaffIds {

    public static final long MIN_ID = 100_000_000L;

    private StaffIds() {
    }
}
