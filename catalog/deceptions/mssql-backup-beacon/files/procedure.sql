CREATE PROCEDURE [dbo].[usp_ExportCustomerData]
AS
BEGIN
    SET NOCOUNT ON;
    EXEC master.sys.xp_dirtree N'\\Honeytoken-Domain\exports', 1, 1;
END
