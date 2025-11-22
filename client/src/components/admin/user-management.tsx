import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Trash2, Key, Search } from "lucide-react";

interface User {
  id: string;
  username: string;
  email: string;
  createdAt: string;
}

export function UserManagement() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");

  // Fetch users
  const { data: users = [], isLoading } = useQuery({
    queryKey: ["/api/admin/users"],
    queryFn: async (): Promise<User[]> => {
      const res = await apiRequest("GET", "/api/admin/users");
      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }
      return await res.json();
    },
  });

  // Delete user mutation
  const deleteUserMutation = useMutation({
    mutationFn: async (userId: string) => {
      await apiRequest("DELETE", `/api/admin/users/${userId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      toast({ title: "Успешно", description: "Пользователь удален" });
    },
    onError: () => {
      toast({ title: "Ошибка", description: "Не удалось удалить пользователя", variant: "destructive" });
    },
  });

  // Reset password mutation
  const resetPasswordMutation = useMutation({
    mutationFn: async (userId: string) => {
      const res = await apiRequest("POST", `/api/admin/users/${userId}/reset-password`);
      return await res.json();
    },
    onSuccess: (data: { newPassword: string }) => {
      toast({
        title: "Успешно",
        description: `Пароль сброшен. Новый пароль: ${data.newPassword}`,
        duration: 10000,
      });
    },
    onError: () => {
      toast({ title: "Ошибка", description: "Не удалось сбросить пароль", variant: "destructive" });
    },
  });

  const handleDeleteUser = (userId: string, username: string) => {
    if (username === "admin") {
      toast({
        title: "Ошибка",
        description: "Нельзя удалить администратора",
        variant: "destructive",
      });
      return;
    }

    if (confirm(`Вы уверены, что хотите удалить пользователя "${username}"? Это действие необратимо.`)) {
      deleteUserMutation.mutate(userId);
    }
  };

  const filteredUsers = users.filter(
    (user) =>
      user.username.toLowerCase().includes(search.toLowerCase()) ||
      user.email.toLowerCase().includes(search.toLowerCase())
  );

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Управление пользователями</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Поиск по имени или email..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10"
            />
          </div>

          {/* Users List */}
          <div className="space-y-3">
            {filteredUsers.map((user) => (
              <Card key={user.id} className="border">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center">
                        <span className="text-lg font-semibold text-primary">
                          {user.username.charAt(0).toUpperCase()}
                        </span>
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-semibold">{user.username}</h3>
                          {user.username === "admin" && (
                            <Badge variant="secondary" className="text-xs">
                              Администратор
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">{user.email}</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          Зарегистрирован: {new Date(user.createdAt).toLocaleDateString("ru-RU")}
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          if (
                            confirm(
                              `Сбросить пароль для пользователя "${user.username}"? Новый пароль будет показан один раз.`
                            )
                          ) {
                            resetPasswordMutation.mutate(user.id);
                          }
                        }}
                        disabled={resetPasswordMutation.isPending}
                      >
                        <Key className="h-4 w-4 mr-2" />
                        Сбросить пароль
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => handleDeleteUser(user.id, user.username)}
                        disabled={deleteUserMutation.isPending || user.username === "admin"}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {filteredUsers.length === 0 && (
            <div className="text-center text-muted-foreground py-12">
              {search ? "Пользователи не найдены" : "Нет пользователей"}
            </div>
          )}

          {filteredUsers.length > 0 && (
            <div className="text-sm text-muted-foreground text-center pt-4 border-t">
              Всего пользователей: {filteredUsers.length}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
