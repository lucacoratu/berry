export default function Layout({
    children,
  }: {
    children: React.ReactNode
  }) {
    return (
        <main className="flex flex-col gap-1 p-4 md:gap-6 md:px-8">
            {children}
        </main>
    )
}
