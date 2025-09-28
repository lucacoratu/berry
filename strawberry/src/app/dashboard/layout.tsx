import Navbar from "@/components/navbar";

export default function DashboardLayout({
    children,
  }: Readonly<{
    children: React.ReactNode;
  }>) {
    return (
        <main className="flex min-h-screen w-full flex-col bg-muted">
            <div className="sticky top-0 z-30 flex flex-col sm:gap-4 sm:py-4 bg-background border-b border-secondary">
              <Navbar/>
            </div>
            <div className="relative sm:py-4 sm:px-4">
                {children}
            </div>
        </main>
    );
  }
  