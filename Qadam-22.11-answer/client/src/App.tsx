import { Switch, Route } from "wouter";
import { Suspense, lazy } from "react";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider } from "./hooks/use-auth";
import { ThemeProvider } from "./components/theme-provider";
import ScreenshotProtection from "./components/ScreenshotProtection";
import NotFound from "@/pages/not-found";
import HomePage from "@/pages/home-page";
import PublicHomePage from "@/pages/public-home-page";
import PublicRankingPage from "@/pages/public-ranking-page";
import PublicTestsPage from "@/pages/public-tests-page";
import AboutPage from "@/pages/about-page";
import AuthPage from "@/pages/auth-page";
import BlockVariantsPage from "@/pages/block-variants";
import TestPage from "@/pages/test-page";
import ResultsPage from "@/pages/results-page";
import ProfilePage from "@/pages/profile-page";
import NotificationsPage from "@/pages/notifications-page";
import RankingPage from "@/pages/ranking-page";
import SubscriptionPage from "@/pages/subscription-page";
import PaymentPage from "@/pages/payment-page";
import { ProtectedRoute } from "./lib/protected-route";

// Lazy load heavy pages for better performance
const AdminPage = lazy(() => import("@/pages/admin-simple"));
const AnalyticsPage = lazy(() => import("@/pages/analytics-page"));

// Loading fallback component
const PageSkeleton = () => (
  <div className="min-h-screen bg-background">
    <div className="container mx-auto px-4 lg:px-6 py-8">
      <div className="space-y-6">
        <div className="h-8 bg-muted rounded animate-pulse"></div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-32 bg-muted rounded animate-pulse"></div>
          ))}
        </div>
      </div>
    </div>
  </div>
);

// Стабильные компоненты-обёртки (вынесены за пределы Router чтобы не пересоздавались)
const DashboardComponent = () => <HomePage />;
const BlockVariantsComponent = () => <BlockVariantsPage />;
const TestPageComponent = () => <TestPage />;
const ResultsComponent = () => <ResultsPage />;
const ProfileComponent = () => <ProfilePage />;
const NotificationsComponent = () => <NotificationsPage />;
const RankingComponent = () => <RankingPage />;
const SubscriptionComponent = () => <SubscriptionPage />;
const PaymentComponent = () => <PaymentPage />;

function Router() {
  return (
    <Switch>
      {/* Public routes */}
      <Route path="/" component={PublicHomePage} />
      <Route path="/public-ranking" component={PublicRankingPage} />
      <Route path="/public-tests" component={PublicTestsPage} />
      <Route path="/about" component={AboutPage} />
      <Route path="/auth" component={AuthPage} />
      <Route path="/public-test/:variantId" component={TestPageComponent} />
      <Route path="/payment/:paymentId" component={PaymentComponent} />
      
      {/* Protected routes */}
      <ProtectedRoute path="/dashboard" component={DashboardComponent} />
      <ProtectedRoute path="/block/:blockId" component={BlockVariantsComponent} />
      <ProtectedRoute path="/test/:variantId" component={TestPageComponent} />
      <ProtectedRoute path="/results" component={ResultsComponent} />
      <ProtectedRoute path="/profile" component={ProfileComponent} />
      <ProtectedRoute path="/notifications" component={NotificationsComponent} />
      <ProtectedRoute path="/analytics" component={() => (
        <Suspense fallback={<PageSkeleton />}>
          <AnalyticsPage />
        </Suspense>
      )} />
      <ProtectedRoute path="/admin" component={() => (
        <Suspense fallback={<PageSkeleton />}>
          <AdminPage />
        </Suspense>
      )} />
      <ProtectedRoute path="/ranking" component={RankingComponent} />
      <ProtectedRoute path="/subscription" component={SubscriptionComponent} />
      
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ThemeProvider>
          <TooltipProvider>
            <ScreenshotProtection />
            <div className="content-protected">
              <Toaster />
              <Router />
            </div>
          </TooltipProvider>
        </ThemeProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
