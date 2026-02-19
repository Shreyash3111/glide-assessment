"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { trpc } from "@/lib/trpc/client";
import { AccountCreationModal } from "@/components/AccountCreationModal";
import { FundingModal } from "@/components/FundingModal";
import { TransactionList } from "@/components/TransactionList";


export default function DashboardPage() {
  const router = useRouter();
  const [isCreatingAccount, setIsCreatingAccount] = useState(false);
  const [fundingAccountId, setFundingAccountId] = useState<number | null>(null);
  const [selectedAccountId, setSelectedAccountId] = useState<number | null>(null);

  const {
  data: accounts,
  refetch: refetchAccounts,
  error,
  isLoading,
} = trpc.account.getAccounts.useQuery();
  const logoutMutation = trpc.auth.logout.useMutation();

  useEffect(() => {
    
  if (error?.data?.code === "UNAUTHORIZED") {
    router.push("/login");
  }
}, [error, router]);

  if (isLoading || error?.data?.code === "UNAUTHORIZED") {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="flex flex-col items-center space-y-4">
        <div className="h-10 w-10 animate-spin rounded-full border-4 border-blue-600 border-t-transparent"></div>
        <p className="text-gray-600 text-sm">Checking session...</p>
      </div>
    </div>
  );
}


  const handleLogout = async () => {
    await logoutMutation.mutateAsync();
    router.push("/");
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
    }).format(amount);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-semibold">SecureBank Dashboard</h1>
            </div>
            <div className="flex items-center">
              <button
                onClick={handleLogout}
                className="ml-4 px-4 py-2 text-sm font-medium text-gray-700 hover:text-gray-900"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="mb-6">
            <h2 className="text-2xl font-bold text-gray-900 mb-4">Your Accounts</h2>

            {accounts && accounts.length > 0 ? (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {accounts.map((account) => (
                  <div
                    key={account.id}
                    className="bg-white overflow-hidden shadow rounded-lg cursor-pointer hover:shadow-lg transition"
                    onClick={() => setSelectedAccountId(account.id)}
                  >
                    <div className="px-4 py-5 sm:p-6">
                      <dt className="text-sm font-medium text-gray-500 truncate">
                        {account.accountType.charAt(0).toUpperCase() + account.accountType.slice(1)} Account
                      </dt>
                      <dd className="mt-1 text-3xl font-semibold text-gray-900">{formatCurrency(account.balance)}</dd>
                      <dd className="mt-1 text-sm text-gray-500">Account: ****{account.accountNumber.slice(-4)}</dd>
                      <dd className="mt-1 text-sm text-gray-500">
                        Status:{" "}
                        <span
                          className={`font-medium ${
                            account.status === "active" ? "text-green-600" : "text-yellow-600"
                          }`}
                        >
                          {account.status}
                        </span>
                      </dd>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setFundingAccountId(account.id);
                        }}
                        className="mt-4 w-full bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700"
                      >
                        Fund Account
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 bg-white rounded-lg shadow">
                <p className="text-gray-500 mb-4">You don't have any accounts yet.</p>
              </div>
            )}

            <button
              onClick={() => setIsCreatingAccount(true)}
              className="mt-4 bg-green-600 text-white px-6 py-2 rounded-md font-medium hover:bg-green-700"
            >
              Open New Account
            </button>
          </div>

          {selectedAccountId && (
            <div className="mt-8">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Transaction History</h3>
              <TransactionList accountId={selectedAccountId} />
            </div>
          )}
        </div>
      </main>

      {isCreatingAccount && (
        <AccountCreationModal
          onClose={() => setIsCreatingAccount(false)}
          onSuccess={() => {
            setIsCreatingAccount(false);
            refetchAccounts();
          }}
        />
      )}

      {fundingAccountId && (
        <FundingModal
          accountId={fundingAccountId}
          onClose={() => setFundingAccountId(null)}
          onSuccess={() => {
            setFundingAccountId(null);
            refetchAccounts();
          }}
        />
      )}
    </div>
  );
}
