package backdoordetected.detection;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class BukkitAPIKnowledgeTest {

  @Test
  void isSafeMethodWithKnownPlayerMethodReturnsTrue() {
    assertTrue(BukkitAPIKnowledge.isSafeMethod("org.bukkit.entity.Player", "getName"));
    assertTrue(BukkitAPIKnowledge.isSafeMethod("org.bukkit.entity.Player", "hasPermission"));
    assertTrue(BukkitAPIKnowledge.isSafeMethod("org.bukkit.Server", "getVersion"));
    assertTrue(BukkitAPIKnowledge.isSafeMethod("org.bukkit.World", "getSeed"));
    assertTrue(BukkitAPIKnowledge.isSafeMethod("org.bukkit.Location", "getX"));
  }

  @Test
  void isSafeMethodWithUnknownMethodReturnsFalse() {
    assertFalse(BukkitAPIKnowledge.isSafeMethod("org.bukkit.entity.Player", "nonexistentMethod"));
    assertFalse(BukkitAPIKnowledge.isSafeMethod("org.bukkit.entity.Player", "getCustomName"));
  }

  @Test
  void isSafeMethodWithUnknownClassReturnsFalse() {
    assertFalse(BukkitAPIKnowledge.isSafeMethod("com.example.Foo", "getName"));
  }

  @Test
  void isSafeMethodWithNullReturnsFalse() {
    assertFalse(BukkitAPIKnowledge.isSafeMethod(null, "getName"));
    assertFalse(BukkitAPIKnowledge.isSafeMethod("org.bukkit.entity.Player", null));
  }

  @Test
  void isTaintedMethodWithKnownReturnsTrue() {
    assertTrue(BukkitAPIKnowledge.isTaintedMethod(
        "org.bukkit.event.player.AsyncPlayerChatEvent", "getMessage"));
    assertTrue(BukkitAPIKnowledge.isTaintedMethod(
        "org.bukkit.entity.Player", "getCustomName"));
    assertTrue(BukkitAPIKnowledge.isTaintedMethod(
        "org.bukkit.inventory.meta.BookMeta", "getPages"));
  }

  @Test
  void isTaintedMethodWithSafeMethodReturnsFalse() {
    assertFalse(BukkitAPIKnowledge.isTaintedMethod("org.bukkit.entity.Player", "getName"));
    assertFalse(BukkitAPIKnowledge.isTaintedMethod("org.bukkit.Server", "getVersion"));
  }

  @Test
  void isTaintedMethodWithUnknownReturnsFalse() {
    assertFalse(BukkitAPIKnowledge.isTaintedMethod("org.bukkit.entity.Player", "nonexistent"));
    assertFalse(BukkitAPIKnowledge.isTaintedMethod("com.example.Foo", "getMessage"));
  }

  @Test
  void isTaintedMethodWithNullReturnsFalse() {
    assertFalse(BukkitAPIKnowledge.isTaintedMethod(null, "getMessage"));
    assertFalse(BukkitAPIKnowledge.isTaintedMethod("org.bukkit.entity.Player", null));
  }

  @Test
  void isBukkitClassReturnsTrueForBukkitPackages() {
    assertTrue(BukkitAPIKnowledge.isBukkitClass("org.bukkit.Bukkit"));
    assertTrue(BukkitAPIKnowledge.isBukkitClass("org.bukkit.entity.Player"));
    assertTrue(BukkitAPIKnowledge.isBukkitClass("org.spigotmc.SpigotConfig"));
    assertTrue(BukkitAPIKnowledge.isBukkitClass("net.md_5.bungee.api.ChatColor"));
  }

  @Test
  void isBukkitClassReturnsFalseForNonBukkit() {
    assertFalse(BukkitAPIKnowledge.isBukkitClass("java.lang.String"));
    assertFalse(BukkitAPIKnowledge.isBukkitClass("com.example.Plugin"));
    assertFalse(BukkitAPIKnowledge.isBukkitClass(""));
  }

  @Test
  void isBukkitClassWithNullReturnsFalse() {
    assertFalse(BukkitAPIKnowledge.isBukkitClass(null));
  }

  @Test
  void taintedMethodOnSignWorks() {
    assertTrue(BukkitAPIKnowledge.isTaintedMethod("org.bukkit.block.Sign", "getLine"));
    assertTrue(BukkitAPIKnowledge.isTaintedMethod("org.bukkit.block.Sign", "getLines"));
  }

  @Test
  void taintedMethodOnItemMetaWorks() {
    assertTrue(BukkitAPIKnowledge.isTaintedMethod(
        "org.bukkit.inventory.meta.ItemMeta", "getDisplayName"));
    assertTrue(BukkitAPIKnowledge.isTaintedMethod(
        "org.bukkit.inventory.meta.ItemMeta", "getLore"));
  }
}
