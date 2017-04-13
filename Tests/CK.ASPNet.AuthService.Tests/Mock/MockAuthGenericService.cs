using CK.DB.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CK.SqlServer;
using System.Threading;

namespace CK.AspNet.AuthService.Tests
{
    public class MockAuthGenericService : IGenericAuthenticationProvider
    {
        readonly MockAuthDatabaseService _db;

        public MockAuthGenericService( MockAuthDatabaseService db, string providerName )
        {
            _db = db;
            ProviderName = providerName;
        }

        public string ProviderName { get; }

        public CreateOrUpdateResult CreateOrUpdateUser(ISqlCallContext ctx, int actorId, int userId, object payload, CreateOrUpdateMode mode = CreateOrUpdateMode.CreateOrUpdate)
        {
            return _db.CreateOrUpdateUser(userId, mode, ProviderName);
        }

        public Task<CreateOrUpdateResult> CreateOrUpdateUserAsync(ISqlCallContext ctx, int actorId, int userId, object payload, CreateOrUpdateMode mode = CreateOrUpdateMode.CreateOrUpdate, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(CreateOrUpdateUser(ctx,actorId,userId,null,mode));
        }

        public void DestroyUser(ISqlCallContext ctx, int actorId, int userId)
        {
            _db.DestroyUser(userId, ProviderName);
        }

        public Task DestroyUserAsync(ISqlCallContext ctx, int actorId, int userId, CancellationToken cancellationToken = default(CancellationToken))
        {
            DestroyUser(ctx,actorId,userId);
            return Task.FromResult(0);
        }

        public int? LoginUser(ISqlCallContext ctx, object payload, bool actualLogin = true)
        {
            Tuple<string, string> byName = payload as Tuple<string, string>;
            if (byName != null) return _db.LoginUser(byName.Item1, byName.Item2, actualLogin, ProviderName);
            Tuple<int, string> byId = payload as Tuple<int, string>;
            if (byId != null) return _db.LoginUser(byId.Item1, byId.Item2, actualLogin, ProviderName);
            return null;
        }

        public Task<int?> LoginUserAsync(ISqlCallContext ctx, object payload, bool actualLogin = true, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult( LoginUser(ctx, payload, actualLogin ));
        }
    }
}
