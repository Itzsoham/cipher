"use client"

import * as React from "react"
import { EntryProvider, useEntries } from "@/lib/vault/entry-store"
import { Button } from "@cipher/ui/components/button"
import { Wand2 } from "lucide-react"
import { EntryDetail } from "./entry-detail"
import { EntryList } from "./entry-list"
import { PasswordGeneratorDialog } from "./password-generator-dialog"

function EntryDashboardInner() {
  const { selectedEntry } = useEntries()
  const [standaloneGeneratorOpen, setStandaloneGeneratorOpen] =
    React.useState(false)

  return (
    <div className="flex h-[calc(100vh-14rem)] min-h-[500px] flex-col overflow-hidden rounded-xl border bg-background shadow-xs">
      {/* Top dashboard helper bar */}
      <div className="flex items-center justify-between border-b bg-muted/30 px-4 py-2 text-xs text-muted-foreground">
        <span>Zero-Knowledge Decrypted Vault Session</span>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 gap-1.5 text-xs hover:text-foreground"
          onClick={() => setStandaloneGeneratorOpen(true)}
        >
          <Wand2 className="size-3.5 text-primary" />
          Password Generator
        </Button>
      </div>

      {/* Main Master-Detail View */}
      <div className="flex flex-1 overflow-hidden">
        <div className="h-full w-80 shrink-0 overflow-hidden md:w-96">
          <EntryList />
        </div>
        <div className="h-full flex-1 overflow-y-auto bg-background">
          <EntryDetail key={selectedEntry?.id ?? "none"} entry={selectedEntry} />
        </div>
      </div>

      <PasswordGeneratorDialog
        open={standaloneGeneratorOpen}
        onOpenChange={setStandaloneGeneratorOpen}
      />
    </div>
  )
}

export interface EntryDashboardProps {
  vk: CryptoKey
  userId: string
}

export function EntryDashboard({ vk, userId }: EntryDashboardProps) {
  return (
    <EntryProvider vk={vk} userId={userId}>
      <EntryDashboardInner />
    </EntryProvider>
  )
}
